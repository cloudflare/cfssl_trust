#!/bin/sh

##############################################
# remove-cert.sh                             #
# Remove certificates from trust bundles     #
##############################################

set -eu

die () {
    echo "$@" > /dev/stderr
    exit 1
}

usage () {
    cat << EOF
Usage: $0 [OPTIONS]

Remove a certificate from the trust database and regenerate bundles.

OPTIONS:
    -s, --serial SERIAL     Certificate serial number (hex format, required)
    -k, --ski SKI          Certificate SKI (hex format, optional but recommended)
    -b, --bundle BUNDLE    Bundle to remove from: ca, int, or both (default: both)
    -d, --db PATH          Path to cert database (default: ./cert.db)
    -h, --help             Show this help message

EXAMPLES:
    # Remove from root bundle only
    $0 --serial D27FBBC1DE359E5216AD6149586099C4 --ski 5673586495f9921ab0122a046279a14015882149 --bundle ca

    # Remove from both bundles
    $0 --serial D27FBBC1DE359E5216AD6149586099C4 --ski 5673586495f9921ab0122a046279a14015882149

    # Remove from intermediate bundle only
    $0 --serial ABC123 --bundle int

EOF
    exit 0
}

# Default values
SERIAL=""
SKI=""
BUNDLE="both"
DATABASE_PATH="./cert.db"

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        -s|--serial)
            SERIAL="$2"
            shift 2
            ;;
        -k|--ski)
            SKI="$2"
            shift 2
            ;;
        -b|--bundle)
            BUNDLE="$2"
            shift 2
            ;;
        -d|--db)
            DATABASE_PATH="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            die "Unknown option: $1. Use -h for help."
            ;;
    esac
done

# Validate required arguments
if [ -z "$SERIAL" ]; then
    die "Error: Serial number is required. Use -s or --serial to specify it."
fi

# Validate bundle option
case "$BUNDLE" in
    ca|int|both)
        ;;
    *)
        die "Error: Invalid bundle option '$BUNDLE'. Must be 'ca', 'int', or 'both'."
        ;;
esac

# Check if database exists
if [ ! -f "$DATABASE_PATH" ]; then
    die "Error: Database not found at $DATABASE_PATH"
fi

# Build WHERE clause
if [ -n "$SKI" ]; then
    WHERE_CLAUSE="ski = '$SKI' AND serial = x'$SERIAL'"
else
    WHERE_CLAUSE="serial = x'$SERIAL'"
fi

echo "==> Removing certificate with serial: $SERIAL"
if [ -n "$SKI" ]; then
    echo "    SKI: $SKI"
fi
echo "    From bundle(s): $BUNDLE"
echo ""

# Backup database
BACKUP_PATH="${DATABASE_PATH}.backup.$(date +%Y%m%d_%H%M%S)"
echo "==> Creating backup: $BACKUP_PATH"
cp "$DATABASE_PATH" "$BACKUP_PATH"

# Remove from appropriate tables
if [ "$BUNDLE" = "ca" ] || [ "$BUNDLE" = "both" ]; then
    echo "==> Removing from root bundle..."
    COUNT=$(sqlite3 "$DATABASE_PATH" "SELECT COUNT(*) FROM roots WHERE $WHERE_CLAUSE;")
    if [ "$COUNT" -gt 0 ]; then
        sqlite3 "$DATABASE_PATH" "DELETE FROM roots WHERE $WHERE_CLAUSE;"
        echo "    Removed $COUNT entries from roots table"
    else
        echo "    No entries found in roots table"
    fi
fi

if [ "$BUNDLE" = "int" ] || [ "$BUNDLE" = "both" ]; then
    echo "==> Removing from intermediate bundle..."
    COUNT=$(sqlite3 "$DATABASE_PATH" "SELECT COUNT(*) FROM intermediates WHERE $WHERE_CLAUSE;")
    if [ "$COUNT" -gt 0 ]; then
        sqlite3 "$DATABASE_PATH" "DELETE FROM intermediates WHERE $WHERE_CLAUSE;"
        echo "    Removed $COUNT entries from intermediates table"
    else
        echo "    No entries found in intermediates table"
    fi
fi

# Check if certificate is still referenced
ROOT_COUNT=$(sqlite3 "$DATABASE_PATH" "SELECT COUNT(*) FROM roots WHERE $WHERE_CLAUSE;")
INT_COUNT=$(sqlite3 "$DATABASE_PATH" "SELECT COUNT(*) FROM intermediates WHERE $WHERE_CLAUSE;")

if [ "$ROOT_COUNT" -eq 0 ] && [ "$INT_COUNT" -eq 0 ]; then
    echo "==> Certificate no longer referenced, removing from certificates table..."
    sqlite3 "$DATABASE_PATH" "DELETE FROM certificates WHERE $WHERE_CLAUSE;"
    echo "    Removed from certificates table"
fi

echo ""
echo "==> Regenerating bundles..."

# Get the latest release for each bundle type
if [ "$BUNDLE" = "ca" ] || [ "$BUNDLE" = "both" ]; then
    LATEST_CA=$(cfssl-trust -d "$DATABASE_PATH" -b ca releases | awk 'NR==1 { print $2 }')
    if [ -n "$LATEST_CA" ]; then
        echo "==> Regenerating ca-bundle.crt (release: $LATEST_CA)..."
        cfssl-trust -d "$DATABASE_PATH" -r "$LATEST_CA" -b ca bundle ca-bundle.crt
        echo "==> Regenerating certdata/ca-bundle.txt..."
        certdump ca-bundle.crt > certdata/ca-bundle.txt
        echo "    ca-bundle.crt and certdata/ca-bundle.txt updated"
    else
        echo "    Warning: No CA releases found"
    fi
fi

if [ "$BUNDLE" = "int" ] || [ "$BUNDLE" = "both" ]; then
    LATEST_INT=$(cfssl-trust -d "$DATABASE_PATH" -b int releases | awk 'NR==1 { print $2 }')
    if [ -n "$LATEST_INT" ]; then
        echo "==> Regenerating int-bundle.crt (release: $LATEST_INT)..."
        cfssl-trust -d "$DATABASE_PATH" -r "$LATEST_INT" -b int bundle int-bundle.crt
        echo "==> Regenerating certdata/int-bundle.txt..."
        certdump int-bundle.crt > certdata/int-bundle.txt
        echo "    int-bundle.crt and certdata/int-bundle.txt updated"
    else
        echo "    Warning: No intermediate releases found"
    fi
fi

echo ""
echo "==> Done! Certificate removed and bundles regenerated."
echo "    Backup saved at: $BACKUP_PATH"
