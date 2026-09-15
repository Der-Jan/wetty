import { promptAgentAction } from './approvalPrompt';

export type ForwardApproval = (
  user: string,
  signal: AbortSignal,
  initialLogin?: boolean,
) => Promise<boolean> | boolean;
export const promptForwardSign: ForwardApproval = (
  user,
  signal,
  initialLogin = false,
) =>
  promptAgentAction(
    initialLogin
      ? 'Use imported SSH key for login?'
      : 'Allow forwarded SSH authentication?',
    initialLogin
      ? `Log in to your configured SSH server as ${user}? This request expires in 45 seconds.`
      : `A remote process requests use of your browser key to log in as ${user}. The destination is not verified by this browser. Approve only if you just started this SSH or Git operation. This request expires in 45 seconds.`,
    'Allow once',
    signal,
  );
