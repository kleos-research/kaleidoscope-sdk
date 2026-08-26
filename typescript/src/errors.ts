export class IntegrationError extends Error {
  readonly code: string = "integration_error";
}

export class DescriptorError extends IntegrationError {
  override readonly code: string = "invalid_descriptor";
}

export class MissingBinaryError extends DescriptorError {
  override readonly code: string = "missing_binary";
}

export class ChildProcessError extends IntegrationError {
  override readonly code: string = "child_crash";
}

/**
 * The literal string substituted for `{key_file}` when the engine could not
 * tell us where its key file lives. Pinned so a rendered message is comparable
 * across the two SDKs.
 */
export const MISSING_KEY_FILE_PLACEHOLDER = "the key file";

/**
 * The SDK's own actionable text for every entitlement refusal, one template per
 * identifier, byte-identical to reference/entitlement-contract-v1.json and to
 * the Python SDK's copy.
 *
 * These are NOT the engine's prose. The engine's prose is attached separately
 * as `diagnostic`, bounded and redacted, and is never the instruction the user
 * reads: the redaction rewrites the engine's own instructional
 * `KALEIDOSCOPE_API_KEY=ksk_alpha....` line to `KALEIDOSCOPE_API_KEY=<redacted>`,
 * destroying exactly the sentence that would have helped.
 *
 * `{key_file}` is the only placeholder. It appears in every template that tells
 * the user where to put a key -- five of them, since the code route was added.
 */
export const ENTITLEMENT_MESSAGES: Readonly<Record<string, string>> = Object.freeze({
  E_NO_KEY: [
    "Kaleidoscope alpha: no API key was found, so the engine refused to start.",
    "Pass it as api_key= when you construct the client, set KALEIDOSCOPE_API_KEY in",
    "your environment, or write the key to {key_file} with permissions 0600.",
    "Ask the alpha owner for a key if you do not have one.",
    "Your local vault data is intact and unchanged.",
  ].join("\n"),
  E_KEY_FILE_UNUSABLE: [
    "Kaleidoscope alpha: the key file at {key_file} could not be used.",
    "It must be a regular file, no larger than 256 bytes, owned by you and set to",
    "permissions 0600, containing the key and nothing else.",
    "Your local vault data is intact and unchanged.",
  ].join("\n"),
  E_MALFORMED_KEY: [
    "Kaleidoscope alpha: the API key is not a well-formed alpha key.",
    'It must be "ksk_alpha." followed by 43 characters. Check for a truncated',
    "paste, a stray quote, or surrounding whitespace.",
    "Your local vault data is intact and unchanged.",
  ].join("\n"),
  E_UNVERIFIED: [
    "Kaleidoscope alpha: this API key has not been verified on this machine yet.",
    "A background revalidation has been started. Connect to the network and try",
    "again. If it keeps failing, ask the alpha owner to confirm the key is active.",
    "Your local vault data is intact and unchanged.",
  ].join("\n"),
  E_UNKNOWN_KEY: [
    "Kaleidoscope alpha: the control plane does not recognise this API key.",
    "This is not a revocation. Check for a truncated paste, then ask the alpha owner",
    "to confirm the key was issued for this alpha.",
    "Pass it as api_key= when you construct the client, set KALEIDOSCOPE_API_KEY in",
    "your environment, or write the key to {key_file} with permissions 0600.",
    "Your local vault data is intact and unchanged.",
  ].join("\n"),
  E_REVOKED: [
    "Kaleidoscope alpha: this API key has been revoked by the alpha owner.",
    "Contact the alpha owner for a replacement key. Nothing you do locally will",
    "restore this one.",
    "Pass it as api_key= when you construct the client, set KALEIDOSCOPE_API_KEY in",
    "your environment, or write the key to {key_file} with permissions 0600.",
    "Your local vault data is intact and unchanged.",
  ].join("\n"),
  E_KEY_EXPIRED: [
    "Kaleidoscope alpha: this API key has expired.",
    "Contact the alpha owner for a replacement key.",
    "Pass it as api_key= when you construct the client, set KALEIDOSCOPE_API_KEY in",
    "your environment, or write the key to {key_file} with permissions 0600.",
    "Your local vault data is intact and unchanged.",
  ].join("\n"),
  E_GRACE_EXPIRED: [
    "Kaleidoscope alpha: this API key could not be revalidated within its grace",
    "window, so gated commands have stopped working.",
    "Reconnect to the network and try again; the key itself may still be fine.",
    "Your local vault data is intact and unchanged.",
  ].join("\n"),
  E_CLOCK_BACKWARDS: [
    "Kaleidoscope alpha: the system clock has moved backwards since the last",
    "entitlement check, so the grace window cannot be evaluated.",
    "Correct the system clock and try again.",
    "Your local vault data is intact and unchanged.",
  ].join("\n"),
  E_UNKNOWN: [
    "Kaleidoscope alpha: the engine refused this command for an entitlement reason",
    "this SDK does not recognise. The engine and this SDK may be different versions.",
    "See the engine diagnostic attached to this error.",
    "Your local vault data is intact and unchanged.",
  ].join("\n"),
});

/**
 * Render one template. An identifier this SDK does not carry a template for
 * renders E_UNKNOWN's text -- never an empty string, because a refusal spelled
 * as an empty answer is the defect class this whole change is written against.
 */
export function renderEntitlementMessage(reason: string, keyFile?: string | undefined): string {
  const template = ENTITLEMENT_MESSAGES[reason] ?? ENTITLEMENT_MESSAGES.E_UNKNOWN;
  const target = keyFile === undefined || keyFile.length === 0
    ? MISSING_KEY_FILE_PLACEHOLDER
    : keyFile;
  return (template as string).split("{key_file}").join(target);
}

/**
 * The engine refused a gated command for an alpha entitlement reason.
 *
 * Not a ChildProcessError: the child started fine and refused deliberately,
 * which is the distinction this module exists to keep. It sits beside
 * NativeRefusalError, which is here for the same reason.
 *
 * `message` is this SDK's own actionable text (reference/
 * entitlement-contract-v1.json). `diagnostic` is the engine's bounded,
 * redacted stderr, attached as evidence and never as the instruction.
 */
export class EntitlementError extends IntegrationError {
  override readonly code: string = "entitlement";
  readonly reason: string;
  readonly diagnostic: string;
  readonly keyFile: string | undefined;

  /**
   * `cause` carries the transport failure the refusal was diagnosed from, when
   * there was one. Python raises `... from exc` on the MCP path, so without it
   * a caller inspecting the cause chain saw `McpError: Connection closed` in
   * one language and nothing in the other -- for the same refusal, from the
   * same engine. The two are pinned together by the behaviour golden now.
   */
  constructor(
    reason: string,
    options: { diagnostic?: string; keyFile?: string; cause?: unknown } = {},
  ) {
    super(renderEntitlementMessage(reason, options.keyFile));
    if (options.cause !== undefined) this.cause = options.cause;
    this.reason = reason;
    this.diagnostic = options.diagnostic ?? "";
    this.keyFile = options.keyFile;
  }
}

export class ManagerCommandError extends ChildProcessError {
  override readonly code: string = "manager_command";
  readonly arguments: readonly string[];
  readonly returnCode: number;

  constructor(arguments_: readonly string[], returnCode: number, diagnostic: string) {
    const suffix = diagnostic.length > 0 ? `: ${diagnostic}` : "";
    super(`manager command ${JSON.stringify(arguments_.join(" "))} exited ${returnCode}${suffix}`);
    this.arguments = Object.freeze([...arguments_]);
    this.returnCode = returnCode;
  }
}

export class DeadlineExceededError extends ChildProcessError {
  override readonly code: string = "deadline_exceeded";
}

export class ProcessCancelledError extends ChildProcessError {
  override readonly code: string = "cancelled";
}

export class OutputLimitError extends ChildProcessError {
  override readonly code: string = "output_limit";
}

export class ProtocolContractError extends IntegrationError {
  override readonly code: string = "protocol_contract";
}

export class NativeRefusalError extends IntegrationError {
  override readonly code: string = "native_refusal";
  readonly operation: string;
  readonly response: unknown;

  constructor(operation: string, response: unknown) {
    super(`Kaleidoscope refused native operation ${JSON.stringify(operation)}`);
    this.operation = operation;
    this.response = response;
  }
}

export class DuplicateSearchError extends IntegrationError {
  override readonly code: string = "duplicate_search";
}

export class ToolRefusalError extends IntegrationError {
  override readonly code: string = "tool_refusal";
  readonly tool: string;
  readonly text: string;

  constructor(tool: string, text: string) {
    super(`Kaleidoscope refused ${JSON.stringify(tool)}: ${text}`);
    this.tool = tool;
    this.text = text;
  }
}
