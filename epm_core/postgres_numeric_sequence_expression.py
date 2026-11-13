"""Typed ordered expressions lowered to bounded exact rational PostgreSQL SQL."""
from decimal import Decimal

import psycopg
from psycopg.types.json import Jsonb

from .postgres_expression import _expression
from .postgres_jobs import _canonical_digest

COMPILER = 'ordered-numeric-expressions-v2'
PLAN_DIGEST = _canonical_digest({'version': 2, 'function': 'facts.numeric.sequence',
    'types': 'shared_expression_kernel', 'arithmetic': 'exact_integer_rationals',
    'rounding': 'half_even_8_at_statement_boundary_including_add',
    'conditionals': 'only_selected_errors_propagate', 'nodesPerExpression': 64,
    'depth': 12, 'nodesPerProgram': 2048, 'statements': 500,
    'engine': 'postgres_exact_recursive_sql', 'events': 'one_atomic_commit'})


def compile_expression(raw, statement_index):
    def leaves(node):
        op = node.get('op')
        if op in ('StatementAmount', 'StatementPresent'):
            if (set(node) != {'op', 'statementIndex'}
                    or type(node['statementIndex']) is not int
                    or not 0 <= node['statementIndex'] < statement_index):
                raise ValueError('NUMERIC_SEQUENCE_EXPRESSION_REFERENCE_INVALID')
            return dict(node), 'amount' if op == 'StatementAmount' else 'boolean'
        if op in ('CurrentAmount', 'CurrentPresent'):
            if set(node) != {'op'}:
                raise ValueError('NUMERIC_SEQUENCE_EXPRESSION_CURRENT_INVALID')
            return dict(node), 'amount' if op == 'CurrentAmount' else 'boolean'
        if op in ('SourceAmount', 'SourceValue', 'PublishedAmount'):
            raise ValueError('NUMERIC_SEQUENCE_EXPRESSION_SOURCE_UNSUPPORTED')
        return None
    normalized, kind = _expression(raw, leaf_parser=leaves)
    if kind != 'amount':
        raise ValueError('NUMERIC_SEQUENCE_EXPRESSION_AMOUNT_REQUIRED')
    return normalized


def instructions(rows):
    """Postorder fixed instructions; each statement resets its local registers."""
    result = []; budget = 0
    for row in rows:
        local = []
        def visit(node):
            item = {'op': node['op']}
            for field in ('left', 'right', 'test', 'then', 'else'):
                if field in node: item[field + '_index'] = visit(node[field])
            for field in ('statementIndex', 'operator'):
                if field in node: item[field] = node[field]
            if node['op'] in ('AmountLiteral', 'RatioLiteral'):
                n, d = Decimal(node['decimal']).as_integer_ratio()
                item.update(n=str(n), d=str(d))
            index = len(local); local.append(item); return index
        root = None
        if row['op'] != 'clear':
            expression = row.get('expression')
            if expression is None:
                expression = ({'op': 'StatementAmount', 'statementIndex': row['reference']}
                    if row['reference'] is not None else {'op': 'AmountLiteral', 'decimal': row['literal']})
            root = visit(expression)
        budget += len(local)
        if budget > 2048: raise ValueError('NUMERIC_SEQUENCE_EXPRESSION_PROGRAM_BUDGET')
        local.append({'op': 'Publish', 'root_index': root, 'mutation': row['op']})
        for index, item in enumerate(local):
            result.append({**item, 'step': len(result) + 1, 'local_index': index,
                'statement_ordinal': row['ordinal'], 'series_key': row['series_key']})
    return result


def evaluate_trace(db, rows, initial):
    tape = instructions(rows)
    result = evaluate_partitions(db, tape, [{'partition_key': '', 'states': initial}])
    return [{key: value for key, value in row.items() if key != 'partition_key'}
            for row in result]


def evaluate_partitions(db, tape, partitions, *, exact_results=False):
    """Run the same exact instruction kernel for independent input states.

    Ordered sequences use one partition; selected transforms use one bounded
    partition per existing fact. Arithmetic and boundary rounding are identical.
    """
    if type(exact_results) is not bool:
        raise ValueError('NUMERIC_SEQUENCE_EXACT_MODE_INVALID')
    if exact_results and any(item.get('op') in (
            'StatementAmount', 'StatementPresent', 'CurrentAmount', 'CurrentPresent')
            or item.get('op') == 'Publish' and item.get('mutation') != 'set'
            for item in tape):
        raise ValueError('NUMERIC_SEQUENCE_EXACT_PREPARED_INPUT_REQUIRED')
    # The opt-in prepared-input projection exposes the same exact register
    # arithmetic. It must not evaluate an eight-place rounded cast first.
    rounding_sql = "NULL::numeric" if exact_results else """CASE WHEN i.op='Publish' AND i.mutation<>'clear'
                AND coalesce(value.cell->>'error','')='' THEN
                (sign(scaled.n)*(remainder.q+CASE WHEN remainder.r*2>scaled.d OR
                    (remainder.r*2=scaled.d AND mod(remainder.q,2)=1) THEN 1 ELSE 0 END)/100000000)::numeric(28,8)
                ELSE NULL END"""
    result_sql = ("partition_key,statement_ordinal ordinal,"
        "(registers->-1->>'n')::numeric numerator,"
        "(registers->-1->>'d')::numeric denominator,error" if exact_results else
        "partition_key,statement_ordinal ordinal,amount,before_amount,error")
    try:
        trace = db.execute(f'''WITH RECURSIVE input AS (
            SELECT * FROM jsonb_to_recordset(%s::jsonb) i(step int,local_index int,
                statement_ordinal int,series_key text,op text,n numeric,d numeric,
                "statementIndex" int,operator text,left_index int,right_index int,
                test_index int,then_index int,else_index int,root_index int,mutation text)),
        execution(partition_key,step,states,history,registers,statement_ordinal,amount,before_amount,error,published) AS (
            SELECT p.partition_key,0,p.states,'[]'::jsonb,'[]'::jsonb,0,NULL::numeric,0::numeric,''::text,false
            FROM jsonb_to_recordset(%s::jsonb) p(partition_key text,states jsonb)
            UNION ALL
            SELECT e.partition_key,i.step,
                CASE WHEN i.op='Publish' THEN jsonb_set(e.states,ARRAY[i.series_key],outcome.cell) ELSE e.states END,
                CASE WHEN i.op='Publish' THEN e.history || jsonb_build_array(outcome.cell) ELSE e.history END,
                CASE WHEN i.local_index=0 THEN '[]'::jsonb ELSE e.registers END || jsonb_build_array(value.cell),
                i.statement_ordinal,rounded.amount,prior.amount,
                coalesce(value.cell->>'error',''),i.op='Publish'
            FROM execution e JOIN input i ON i.step=e.step+1
            CROSS JOIN LATERAL (SELECT e.registers->i.left_index a,e.registers->i.right_index b,
                e.registers->i.test_index test,e.registers->i.then_index yes,e.registers->i.else_index no,
                e.registers->i.root_index root,
                e.history->i."statementIndex" statement,
                e.states->i.series_key current) registers
            CROSS JOIN LATERAL (SELECT (registers.a->>'n')::numeric an,(registers.a->>'d')::numeric ad,
                (registers.b->>'n')::numeric bn,(registers.b->>'d')::numeric bd,
                coalesce((registers.current->>'amount')::numeric,0) amount) prior
            CROSS JOIN LATERAL (SELECT CASE i.op
                WHEN 'Add' THEN prior.an*prior.bd+prior.bn*prior.ad
                WHEN 'Subtract' THEN prior.an*prior.bd-prior.bn*prior.ad
                WHEN 'Multiply' THEN prior.an*prior.bn
                WHEN 'Divide' THEN prior.an*prior.bd*sign(prior.bn) END n,
                CASE WHEN i.op='Divide' THEN prior.ad*abs(prior.bn) ELSE prior.ad*prior.bd END d,
                CASE i.operator WHEN 'eq' THEN prior.an*prior.bd=prior.bn*prior.ad
                    WHEN 'ne' THEN prior.an*prior.bd<>prior.bn*prior.ad
                    WHEN 'lt' THEN prior.an*prior.bd<prior.bn*prior.ad
                    WHEN 'le' THEN prior.an*prior.bd<=prior.bn*prior.ad
                    WHEN 'gt' THEN prior.an*prior.bd>prior.bn*prior.ad
                    WHEN 'ge' THEN prior.an*prior.bd>=prior.bn*prior.ad END boolean) arithmetic
            CROSS JOIN LATERAL (SELECT CASE
                WHEN i.op IN ('AmountLiteral','RatioLiteral') THEN jsonb_build_object('n',i.n,'d',i.d,'error','')
                WHEN i.op IN ('StatementPresent','CurrentPresent') THEN jsonb_build_object('boolean',
                    coalesce((CASE WHEN i.op='StatementPresent' THEN registers.statement ELSE registers.current END->>'present')::boolean,false),'error','')
                WHEN i.op IN ('StatementAmount','CurrentAmount') THEN jsonb_build_object('n',
                    (CASE WHEN i.op='StatementAmount' THEN registers.statement ELSE registers.current END->>'amount')::numeric*100000000,
                    'd',100000000,'error',CASE WHEN coalesce((CASE WHEN i.op='StatementAmount'
                    THEN registers.statement ELSE registers.current END->>'present')::boolean,false) THEN '' ELSE 'missing' END)
                WHEN i.op='If' THEN CASE WHEN coalesce(registers.test->>'error','')<>'' THEN registers.test
                    WHEN (registers.test->>'boolean')::boolean THEN registers.yes ELSE registers.no END
                WHEN i.op='Publish' THEN CASE WHEN i.mutation='clear' THEN jsonb_build_object('error','') ELSE registers.root END
                ELSE jsonb_build_object('n',arithmetic.n,'d',arithmetic.d,'boolean',arithmetic.boolean,
                    'error',CASE WHEN coalesce(registers.a->>'error','')<>'' THEN registers.a->>'error'
                    WHEN coalesce(registers.b->>'error','')<>'' THEN registers.b->>'error'
                    WHEN i.op='Divide' AND prior.bn=0 THEN 'division' ELSE '' END) END cell) value
            CROSS JOIN LATERAL (SELECT (value.cell->>'n')::numeric*100000000+
                CASE WHEN i.mutation='add' THEN prior.amount*100000000*(value.cell->>'d')::numeric ELSE 0 END n,
                (value.cell->>'d')::numeric d) scaled
            CROSS JOIN LATERAL (SELECT div(abs(scaled.n),nullif(scaled.d,0)) q,
                mod(abs(scaled.n),nullif(scaled.d,0)) r) remainder
            CROSS JOIN LATERAL (SELECT {rounding_sql} amount) rounded
            CROSS JOIN LATERAL (SELECT jsonb_build_object('present',i.mutation<>'clear','amount',rounded.amount) cell) outcome)
        SELECT {result_sql} FROM execution
        WHERE published ORDER BY partition_key,statement_ordinal''', (Jsonb(tape), Jsonb(partitions))).fetchall()
    except psycopg.errors.NumericValueOutOfRange as error:
        raise ValueError('NUMERIC_SEQUENCE_AMOUNT_OUT_OF_RANGE') from error
    for row in trace:
        if row['error'] == 'missing': raise ValueError('NUMERIC_SEQUENCE_REFERENCED_VALUE_MISSING')
        if row['error'] == 'division': raise ValueError('NUMERIC_SEQUENCE_DIVISION_BY_ZERO')
    return trace
