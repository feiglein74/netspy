# Universal Background Process Management Rules

## Core Principle
**Every process you start MUST be cleaned up before session end.**

## The Problem
Claude Code tracks background processes via Shell-IDs. When processes complete but Shell-IDs remain active:
- Endless system reminders appear
- Token budget gets wasted
- Session context gets polluted
- After `/compact`, orphaned Shell-IDs cause persistent noise

## Universal Rules (for ANY coding project)

### Rule 1: Avoid Background Processes
**Default stance**: Don't start background processes unless absolutely necessary.

```bash
# ❌ AVOID
long_running_command &  # Creates background process

# ✅ PREFER
long_running_command    # Run synchronously, wait for completion
```

### Rule 2: Temporary Files → Immediate Cleanup
**Pattern**: Create → Use → Delete in ONE command chain

```bash
# ❌ WRONG - File persists, may create background process
echo "test" > temp.txt
some_command temp.txt
rm temp.txt  # Too late - Shell-ID already created

# ✅ RIGHT - Atomic operation
echo "test" > temp.txt && some_command temp.txt && rm temp.txt

# ✅ BETTER - No file at all
some_command <(echo "test")

# ✅ BEST - Inline heredoc (language-specific)
go run <<'EOF'
package main
func main() { /* code */ }
EOF
```

### Rule 3: Test Scripts Protocol
For temporary test/debug scripts:

```bash
# Pattern: test_<purpose>.{ext}
# Examples: test_api.py, test_parse.go, test_regex.js

# ✅ Always use && for cleanup
echo "code" > test_foo.py && python test_foo.py && rm test_foo.py

# ✅ Or wrap in function
run_test() {
  local file=$1
  shift
  echo "$@" > "$file" && bash "$file" && rm "$file"
}
```

### Rule 4: Long-Running Processes
If background process is unavoidable (builds, installs, servers):

```bash
# ✅ Document PID immediately
long_command &
PROCESS_PID=$!
echo "Started process: $PROCESS_PID"

# ✅ Set timeout
timeout 300 long_command  # 5 min max

# ✅ Track and cleanup
wait $PROCESS_PID
echo "Process completed with exit code: $?"
```

### Rule 5: Session-End Checklist
Before `/compact` or session end:

```bash
# Check for orphaned processes
ps aux | grep -E "(test_|temp_|debug_)" | grep -v grep

# Check for temporary files
ls test_* temp_* debug_* 2>/dev/null

# Kill if necessary
pkill -f 'test_'
rm -f test_* temp_* debug_*
```

## Language-Specific Patterns

### Go
```bash
# ✅ Inline test
go run <<'EOF'
package main
import "fmt"
func main() { fmt.Println("test") }
EOF

# ✅ With file cleanup
echo 'package main...' > test.go && go run test.go && rm test.go
```

### Python
```bash
# ✅ Inline
python3 -c 'print("test")'

# ✅ With file
echo 'print("test")' > test.py && python3 test.py && rm test.py
```

### Node.js
```bash
# ✅ Inline
node -e 'console.log("test")'

# ✅ With file
echo 'console.log("test")' > test.js && node test.js && rm test.js
```

### Shell
```bash
# ✅ Process substitution
some_command <(echo "test data")

# ✅ Heredoc
some_command <<'EOF'
test data
EOF
```

## Common Patterns

### Pattern: Quick Test
```bash
# Create → Test → Delete (atomic)
create_test && run_test && delete_test
```

### Pattern: Debug Output
```bash
# Use process substitution instead of temp files
diff <(command1) <(command2)
```

### Pattern: Build Artifacts
```bash
# If build creates temp files, clean them up
make build && ./output && make clean
```

## Red Flags 🚩

Watch out for commands that commonly create background processes:

- `go run test_*.go` (without cleanup)
- `npm install` (in background)
- `docker build` (without wait)
- `brew install` (long-running)
- Any command with `&` at the end

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────┐
│ BACKGROUND PROCESS RULES                                │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  1. Avoid background processes                          │
│  2. Temp files → immediate cleanup (&&)                 │
│  3. Test scripts → atomic create/run/delete             │
│  4. Long processes → document PID, set timeout          │
│  5. Before session end → check & cleanup                │
│                                                          │
│  Pattern: create && use && delete                       │
│  Never:   create ... use ... delete (separate)          │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

## Benefits

Following these rules ensures:
- ✅ Clean sessions without process noise
- ✅ Efficient token usage (no endless reminders)
- ✅ Reproducible development environment
- ✅ No orphaned processes consuming resources
- ✅ Works across all platforms (macOS, Linux, Windows)

## Integration

### Option 1: Project-Specific (recommended for now)
Copy this file to each project's repository as `BACKGROUND_PROCESS_RULES.md`

### Option 2: Global Claude Code Settings (future)
Could be integrated into `.claude/` global configuration when that feature is available

### Option 3: Team Standards
Add to your team's development guidelines document
