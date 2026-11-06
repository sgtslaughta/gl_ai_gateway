# Request to GitLab administrators: AI instance runner

Status: ready to send. Nothing has been created yet.

Hello,

We ask for one instance runner for AI jobs. It runs on our own cluster. We
look after the runner host and its configuration. We need three actions from
a GitLab admin.

1. Create an instance runner with the tag `ai`. Turn **Run untagged jobs** off.
2. Set its maximum job timeout to 1800 seconds.
3. Send us the runner authentication token through a secure channel. Do not use email or chat.

What the runner does:
- It runs only jobs that carry the `ai` tag.
- Jobs run in short-lived pods on dedicated nodes, with a network policy that allows only GitLab, our registry, our token service, our gateway and DNS.
- Only images from our hardened registry path can run.

What we ask in return:
- Tell us before you pause, edit or delete this runner, or change its tags.
- Tell us the runner's numeric ID after creation, and again if it changes. Our token service only accepts listed runner IDs.
- Do not share the token. Whoever holds it can pick up users' jobs and their ID tokens.

Please note the trust involved: GitLab admins can change runner settings and
may act as other users. Our sign-off material records this.

Who to contact: <team contact, to be filled in>
Needed by: <date, to be filled in>
