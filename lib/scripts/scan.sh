#!/usr/bin/env bash

# DEFAULT VALUES
DEFAULT_SCANNED_JSON_PATH="security/scanned.json"
reference_json="security/reference.json"
scanned_json=""

# Variables
reference_cves=()
scanned_cves=()
exit_code=0

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
        -r | --reference)
            reference_json="$2"
            shift 2
            ;;
        -s | --scanned)
            scanned_json="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1"
            exit 1
            ;;
        esac
    done
}

audit_dependencies() {
    if [[ -z "$scanned_json" ]]; then
        echo "No scanned .json file provided. Scanning..."
        scanned_json="$DEFAULT_SCANNED_JSON_PATH"
        poetry audit --json >"$scanned_json" || true
        return
    fi
}

print_cves() {
    local cves="$1"
    local cve_count

    if [[ -z "$1" ]]; then
        cve_count=0
    else
        cve_count=$(echo "$cves" | wc -l)
    fi

    echo "----Vulnerabilities ($cve_count) ----"
    if [[ "$cve_count" -gt 0 ]]; then
        echo "$cves"
    fi
    echo "----------------------------"
}

parse_cves_from_json() {

    local query='.vulnerabilities[].vulns[].cve'
    local cves

    echo "Parsing REFERENCE CVEs"
    cves=$(jq -r "$query" "$reference_json" | grep -v '^\s*$' | sort)
    readarray -t reference_cves <<<"$cves"
    print_cves "$cves"

    echo "Parsing SCANNED CVEs"
    cves=$(jq -r "$query" "$scanned_json" | grep -v '^\s*$' | sort)
    readarray -t scanned_cves <<<"$cves"
    print_cves "$cves"

}

validate_cves() {

    if [[ -z "${scanned_cves[*]}" ]]; then
        echo "NO VULNERABILITIES FOUND"
        return 0
    fi

    # Check whether all scanned CVEs are in the reference list
    for cve in "${scanned_cves[@]}"; do
        if ! printf '%s\n' "${reference_cves[@]}" | grep -q "^$cve$"; then
            echo "Found SCANNED CVEs outside of REFERENCE!"
            return 1
        fi
    done

    # Return
    echo "All SCANNED CVEs are part of REFERENCE CVEs"
    return 0

}

main() {
    parse_arguments "$@"

    audit_dependencies

    echo "Parsing CVE JSONs..."
    parse_cves_from_json

    echo "Validating CVES..."
    if validate_cves; then
        echo "----------PASS----------"
        exit_code=0
    else
        echo "----------FAIL----------"
        exit_code=1
    fi
}

main "$@"
return "$exit_code"