"""Transport-neutral cooperative HTTP envelope with inherited core deadlines."""
import asyncio
import json
import time
from .postgres_execution_scope import tool_execution_scope

class HTTPRequestDeadlineUnknown(TimeoutError):
    """A started response cannot safely be replaced after deadline expiry."""

async def bounded_request(application,scope,receive,send,*,seconds,response_seconds):
    deadline = time.monotonic()+seconds
    timer = asyncio.timeout_at(deadline)
    response_started = False
    async def tracked_send(message):
        nonlocal response_started
        if message['type'] == 'http.response.start':
            # A cancellation while sending headers cannot safely send a
            # second response, even if network delivery was incomplete.
            response_started = True
        await send(message)
    try:
        with tool_execution_scope(deadline):
            async with timer:
                await application(scope, receive, tracked_send)
    except BaseException as error:
        if isinstance(error,(SystemExit,KeyboardInterrupt)) or not timer.expired():
            raise
        if response_started:
            raise HTTPRequestDeadlineUnknown('HTTP_REQUEST_DEADLINE_OUTCOME_UNKNOWN') from None
        # The executor independently inherits the same absolute deadline.
        # Give only the timeout response a short delivery grace.
        async with asyncio.timeout(response_seconds):
            await send({'type':'http.response.start','status':504,'headers':[
                (b'content-type',b'application/json'),(b'cache-control',b'no-store'),
                (b'retry-after',b'1')]})
            await send({'type':'http.response.body','body':json.dumps({
                'error':'HTTP_REQUEST_DEADLINE_OUTCOME_UNKNOWN',
                'retry':'inspect durable status and reuse the original request key'}).encode()})
