import type { Scope } from "./types";

export type TaskProgressState =
  | "attention"
  | "inProgress"
  | "succeeded"
  | "other";

export type TaskListRow = {
  taskId: string;
  sequence: number;
  function: string;
  status: string;
  progressState: TaskProgressState;
};

export type TaskListPage<T extends TaskListRow> = {
  tasks: T[];
  nextSequence: number;
  hasMore: boolean;
};

export const taskListBody = (
  scope: Scope,
  afterSequence = 0,
  attentionOnly = false,
) => ({
  ...scope,
  afterSequence,
  limit: 100,
  attentionOnly,
});

export function isTaskProgressState(
  value: unknown,
): value is TaskProgressState {
  return (
    value === "attention" ||
    value === "inProgress" ||
    value === "succeeded" ||
    value === "other"
  );
}

export function mergeTaskListPage<T extends TaskListRow>(
  current: readonly T[],
  page: TaskListPage<T>,
  previousCursor: number,
  append: boolean,
): TaskListPage<T> {
  if (!page || !Array.isArray(page.tasks) || typeof page.hasMore !== "boolean")
    throw new Error("Task continuation response is invalid.");
  const tasks = append ? [...current] : [];
  const identifiers = new Set(tasks.map((task) => task.taskId));
  let cursor = previousCursor;
  for (const task of page.tasks) {
    if (
      !task ||
      typeof task.taskId !== "string" ||
      !task.taskId ||
      typeof task.function !== "string" ||
      typeof task.status !== "string" ||
      !isTaskProgressState(task.progressState)
    )
      throw new Error("Task continuation contains an invalid task.");
    if (identifiers.has(task.taskId))
      throw new Error("Task continuation repeated a task.");
    if (
      !Number.isSafeInteger(task.sequence) ||
      task.sequence <= 0 ||
      (cursor !== 0 && task.sequence >= cursor)
    )
      throw new Error("Task continuation is out of order.");
    cursor = task.sequence;
    identifiers.add(task.taskId);
    tasks.push(task);
  }
  if (page.nextSequence !== cursor || (page.hasMore && !page.tasks.length))
    throw new Error("Task continuation cursor is invalid.");
  return { tasks, nextSequence: cursor, hasMore: page.hasMore };
}
