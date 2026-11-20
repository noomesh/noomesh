# Who may change who can do what

Covers: which gateway actions only a person may take, the one thing an agent may do among them, and the refusal it gets otherwise.

Keys never manage keys or people. A service key, a token exchanged from one (`POST /api/identity/token`), an MCP door token, an in-chat agent's token, an add-on or kiosk token: none of them may change accounts, roles or credentials, whatever role the account behind it holds. A person does that, signed in with `noo auth login` (or the console, or the operator-certificate token). This is in addition to each action's own role check.

## For people

### Actions that need a person

- **Accounts:** create, reset a password, change role or scopes, disable or re-enable, erase, move to another org; create an org.
- **Service keys:** issue, rotate, revoke, retire, revoke-and-disable, set the quota, set the context-overflow mode.
- **Knowledge access:** grant or revoke KB roles; create or delete teams; set KB rules; link or unlink a space to a team.
- **Channel links:** link a channel sender to an account, unlink one.
- **Proposals:** approve or deny a user-management proposal. Filing one (`POST /api/users/propose`, the `noo_user_propose` tool) stays open to agents: it is how an agent asks.
- **Add-on access:** set who may use an add-on feature.
- **Seats and nodes:** mint or revoke a seat token, bind or revoke a seat, approve a node-join proposal, revoke a node bootstrap token.

### The one agent allowance

Minting a node bootstrap token (`POST /api/security/bootstrap-tokens`, also with a Tailscale key) and a bare join key (`POST /api/cluster/mint-join-key`) also admit:

- the MCP **operator** door (`noo_mint_bootstrap_token`, `noo_mint_join_key`, from an `mcp:operator` key), and
- an in-chat agent acting for an **Operator or Admin**.

A person still runs the enrol command on the new machine. Every other agent credential is refused here too, including a token exchanged from an `identity` key.

### The refusal

`403` with a JSON body:

```json
{"error": "a person must do this: sign in as an admin (`noo auth login`) — issuing a service key is not done by a key, a token exchanged from one, or an agent",
 "code": "person_required"}
```

Branch on `code`, not on the sentence. Every refusal writes a `person_required_refused` row to the security audit (`noo security audit list`), naming the action, the kind of credential, and the key consumer behind it when there is one. The token itself is never recorded.

## For agents

- Do not retry a `person_required` answer with another credential. Tell the person what to run, or file a proposal with `noo_user_propose` for an account change.
- To add a machine, call `noo_mint_bootstrap_token` from the operator door; give the person the enrol command it returns.
