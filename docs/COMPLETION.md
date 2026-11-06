# Shell completion

`day2 completion bash` and `day2 completion zsh` print shell scripts generated
from the executable's command parser. They advertise the commands and flags
implemented by that binary, including nested owner and secret commands. They
do not use the historical command inventory as a runtime command catalog.

Generation is offline and does not read credentials, start a browser or contact
an app. Completion does not discover authorized apps or operation IDs. Company
app discovery and `completion refresh-apps` remain planned, as does Fish support.

Run the employee CLI you installed. Use its full path when a separate Platform
operator distribution is also named `day2`; see [installation](INSTALL.md).

For the current Bash session:

```bash
source <(day2 completion bash)
```

For Zsh, save the function in a directory on your completion search path:

```zsh
mkdir -p "$HOME/.local/share/zsh/site-functions"
day2 completion zsh > "$HOME/.local/share/zsh/site-functions/_day2"
fpath=("$HOME/.local/share/zsh/site-functions" $fpath)
autoload -Uz compinit
compinit
```

Keep the `fpath` and `compinit` lines in your shell configuration if desired.
Regenerate the saved function after intentionally updating the employee CLI.
The command prints the script; it does not modify shell configuration or install
files automatically.

Without `--json`, stdout is the script itself. `--json` or `--agent` instead
returns the usual versioned result with `shell` and `script` fields; that JSON
output must not be sourced as a shell script. Bash and Zsh grammar are checked
in both native CI jobs, and an actual Bash completion call checks that implemented
app commands appear while historical placeholders remain absent.
