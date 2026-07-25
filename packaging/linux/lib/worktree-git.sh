#!/usr/bin/env bash

bootstrap_windows_worktree_git() {
  local repository="$1"
  local git_file="$repository/.git"
  local git_line
  local git_directory

  [[ -f "$git_file" && ! -L "$git_file" ]] || return 0
  IFS= read -r git_line <"$git_file" ||
    {
      echo "could not read linked-worktree Git metadata" >&2
      return 1
    }
  case "$git_line" in
    "gitdir: "*) git_directory="${git_line#gitdir: }" ;;
    *) return 0 ;;
  esac
  case "$git_directory" in
    [A-Za-z]:/* | [A-Za-z]:\\*)
      command -v wslpath >/dev/null 2>&1 ||
        {
          echo "Windows linked worktree requires wslpath" >&2
          return 1
        }
      git_directory="$(wslpath -u "$git_directory")"
      [[ -d "$git_directory" && ! -L "$git_directory" ]] ||
        {
          echo "converted linked-worktree Git directory is invalid" >&2
          return 1
        }
      export GIT_DIR="$git_directory"
      export GIT_WORK_TREE="$repository"
      export GIT_OPTIONAL_LOCKS=0
      ;;
  esac
}
