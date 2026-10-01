set shell := ["bash", ".just-shell"]
set positional-arguments

# Show available recipes.
default:
    @just --list

# Run declared fast checks; accepts project-check options such as --json.
lint *args:
    @project-check fast "$@"

# Run the declared full gate; accepts project-check options such as --json.
verify *args:
    @project-check full "$@"
