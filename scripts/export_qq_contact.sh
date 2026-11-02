#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: export_qq_contact.sh --conversation ID --out DIR [options]

Options:
  --days N          Look-back window in days (default: 36500)
  --data-root PATH  QQ data root (default: ~/.config/QQ)
  --account ID      Restrict export to one discovered account
  --overwrite       Allow replacing existing qq_messages.json/html
  -h, --help        Show this help
EOF
}

days=36500
data_root="${HOME:?HOME must be set}/.config/QQ"
conversation=""
out_dir=""
account=""
overwrite=0

while (($#)); do
  case "$1" in
    --days|--data-root|--conversation|--out|--account)
      if (($# < 2)); then
        echo "Missing value for $1" >&2
        exit 2
      fi
      option="$1"
      value="$2"
      shift 2
      case "$option" in
        --days) days="$value" ;;
        --data-root) data_root="$value" ;;
        --conversation) conversation="$value" ;;
        --out) out_dir="$value" ;;
        --account) account="$value" ;;
      esac
      ;;
    --overwrite)
      overwrite=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! "$days" =~ ^[1-9][0-9]*$ ]]; then
  echo "--days must be a positive integer" >&2
  exit 2
fi
if [[ -z "$conversation" || -z "$out_dir" ]]; then
  echo "--conversation and --out are required" >&2
  usage >&2
  exit 2
fi

case "$out_dir" in
  /*) ;;
  *) out_dir="$PWD/$out_dir" ;;
esac

if (( ! overwrite )) && {
  [[ -e "$out_dir/qq_messages.json" ]] || [[ -e "$out_dir/qq_messages.html" ]]
}; then
  echo "Export files already exist in output directory; use --overwrite after reviewing them." >&2
  exit 1
fi

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
cd "$repo_root"

cmd=(python3 -m chatlog_keeper.cli qq --days "$days" --out "$out_dir" --data-root "$data_root" --conversation "$conversation")
if [[ -n "$account" ]]; then
  cmd+=(--account "$account")
fi
exec "${cmd[@]}"
