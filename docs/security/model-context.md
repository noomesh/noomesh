# What the model reads as instructions

Covers: which text reaches a model as instructions and which as data.

Only text the operator controls is in the system message: the persona
prompt, the shipped runbooks and the shipped (core) prompt skills.
Everything a third party could have written travels instead as one fenced
data block at the head of the user's own message, marked as data, with the
begin and end markers made unforgeable and likely injection lines flagged:
retrieved documents, graph facts, memory, other-channel messages, video
recall, conversation summaries and recall (they are built from past
messages), skills written at runtime (evolved, through the API, the
`noo_prompt_skills_create` tool or the evolve add-on) and companion-device
reports. The block is removed again before the session is cached.

Evolved skills are data for this reason: anyone with prompt-skill write
access, an agent through `noo_prompt_skills_create`, or the evolve add-on can
write one. Core skills ship with the product and cannot be edited at runtime,
so they stay instructions.
