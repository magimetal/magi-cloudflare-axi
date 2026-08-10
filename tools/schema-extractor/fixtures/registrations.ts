// Typed registration corpus. Comments, strings, regex, shadowed and foreign calls must not register.
import { z } from "zod";
import type { McpRegistrationContext } from "@repo/mcp-common/src/registration-context";
import { importedSchema } from "./schemas";
import { createPublicMcpApp } from "@repo/mcp-common/src/mcp-app";
import type { McpRegistrationContext as ForeignRegistrationContext } from "evil/registration-context";
import { createPublicMcpApp as createForeignApp } from "evil/mcp-app";

type Env = {};
const names = { static_member: "static_member_name" };
const toolDefinitions = [
  { name: "casb_one", params: { id: z.string(), ref: importedRef } },
  { name: "casb_two", params: { enabled: z.boolean() } },
];

export function registerFixtureTools(context: McpRegistrationContext<Env>) {
  const directSchema = z.object({ id: z.string(), account: accountRef });
  context.registerTool("context_direct", { inputSchema: directSchema });
  context.registerTool("implicit_no_schema");
  registerTool({ name: "dex_local", schema: legacySchema, context });
  registerTool({ name: "foreign_dex_context", schema: legacySchema, context: foreignContext });
  context.accountTool(names.static_member, { inputSchema: importedSchema });
  toolDefinitions.forEach(({ name, params }) => {
    context.accountTool(name, { inputSchema: z.object(params) });
  });
  context.accountTool("outside_casb", { inputSchema: z.object({}) });
  const sameFile = z.object({ local: localRef });
  context.registerTool("same_file_ref", { inputSchema: sameFile });
  context.registerTool("dynamic_expression", { inputSchema: makeSchema() });
  context.registerPrompt("foreign_method", { inputSchema: z.object({}) });
  foreignContext.registerTool("foreign_static", { inputSchema: z.object({}) });
  accountTool("foreign_bare", { inputSchema: z.object({}) });
  const shadowNames = (names: { static_member: string }) =>
    context.accountTool(names.static_member, { inputSchema: z.object({}) });
}

createPublicMcpApp({
  register(context) {
    context.registerTool("inline_app", { inputSchema: z.object({}) });
  },
});
createForeignApp({
  register(context) {
    context.registerTool("foreign_app", { inputSchema: z.object({}) });
  },
});
function spoofedType(context: ForeignRegistrationContext) {
  context.registerTool("foreign_import", { inputSchema: z.object({}) });
}

const registerTool = <T>({ name, schema, context }: {
  name: string;
  schema: T;
  context: McpRegistrationContext<Env>;
}) => context.accountTool(name, { inputSchema: z.object(schema) });

function foreign(registerTool: (tool: unknown) => void) {
  registerTool({ name: "foreign_shadowed", schema: legacySchema });
}
function wrongContext(context: { registerTool: (name: string) => void }) {
  context.registerTool("foreign_context");
}
const quoted = 'registerTool("string_fake")';
const regex = /accountTool("regex_fake")/;
// registerTool({ name: "comment_fake", schema: fake });
