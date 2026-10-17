import { spawn } from "node:child_process";

export interface RunResult {
  platform: NodeJS.Platform;
  argv: string[];
  stdout: string;
  stderr: string;
  code: number | null;
}

export interface CommandRunner {
  run(cmd: string, args: string[], opts?: { timeoutMs?: number }): Promise<RunResult>;
}

/** No shell, ever. Arg arrays only. */
export class LocalExecutor implements CommandRunner {
  async run(
    cmd: string,
    args: string[],
    opts?: { timeoutMs?: number },
  ): Promise<RunResult> {
    return new Promise((resolve, reject) => {
      const child = spawn(cmd, args, {
        shell: false,
        windowsHide: true,
        timeout: opts?.timeoutMs,
      });
      let stdout = "";
      let stderr = "";
      child.stdout?.on("data", (d: Buffer) => (stdout += d.toString()));
      child.stderr?.on("data", (d: Buffer) => (stderr += d.toString()));
      child.on("error", (e: Error) => reject(e));
      child.on("close", (code) => {
        resolve({ platform: process.platform, argv: [cmd, ...args], stdout, stderr, code });
      });
    });
  }
}