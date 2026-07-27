import * as vscode from "vscode";

export function activate() {
  const execution = new vscode.CustomExecution(
    async (): Promise<vscode.Pseudoterminal> => new BuildTerminal(),
  );
  const registration = vscode.tasks.registerTaskProvider(
    "build",
    new InternalTaskProvider(),
  );
  return { execution, registration };
}

class BuildTerminal implements vscode.Pseudoterminal {
  open(_dimensions: vscode.TerminalDimensions | undefined): void {}

  close(): void {}

  staleHelper(): string {
    return "stale";
  }
}

class InternalTaskProvider implements vscode.TaskProvider<vscode.Task> {
  provideTasks(): vscode.Task[] {
    return [];
  }

  resolveTask(task: vscode.Task): vscode.Task {
    return task;
  }

  staleProviderHelper(): string {
    return "stale";
  }
}
