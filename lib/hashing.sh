#!/usr/bin/env bash
# hashing.sh - Hashing and checksum functions for QYVORA Sentinel.

# Source guard - prevent re-sourcing
if [[ "${_SENTINEL_LIB_LOADED:-}" == *"$(basename "${BASH_SOURCE[0]}")"* ]]; then
    return 0 2>/dev/null || true
fi
_SENTINEL_LIB_LOADED="${_SENTINEL_LIB_LOADED:-} $(basename "${BASH_SOURCE[0]}")"

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=logger.sh
source "${SCRIPT_DIR}/logger.sh"

# Detect available hash commands
readonly SENTINEL_SHA256_CMD; SENTINEL_SHA256_CMD="$(_detect_hash_cmd sha256sum shasum -a 256)"
readonly SENTINEL_SHA1_CMD; SENTINEL_SHA1_CMD="$(_detect_hash_cmd sha1sum shasum -a 1)"
readonly SENTINEL_SHA512_CMD; SENTINEL_SHA512_CMD="$(_detect_hash_cmd sha512sum shasum -a 512)"
readonly SENTINEL_MD5_CMD; SENTINEL_MD5_CMD="$(_detect_hash_cmd md5sum md5)"

_detect_hash_cmd() {
    local cmd

    for cmd in "$@"; do
        if command -v "${cmd}" >/dev/null 2>&1; then
            printf '%s' "${cmd}"
            return 0
        fi
    done

    return 1
}

_hash_with_cmd() {
    local -r cmd="${1}"
    local -r target="${2}"

    if [[ -z "${cmd}" ]]; then
        log_error "No hash command available"
        return 1
    fi

    case "${cmd}" in
        sha256sum|sha1sum|sha512sum|md5sum)
            "${cmd}" < "${target}" | awk '{print $1}'
            ;;
        shasum)
            "${cmd}" < "${target}" | awk '{print $1}'
            ;;
        *)
            "${cmd}" < "${target}" | awk '{print $1}'
            ;;
    esac
}

_hash_string_with_cmd() {
    local -r cmd="${1}"
    local -r string="${2}"

    if [[ -z "${cmd}" ]]; then
        log_error "No hash command available"
        return 1
    fi

    printf '%s' "${string}" | "${cmd}" | awk '{print $1}'
}

hash_md5() {
    local -r file="${1}"

    if [[ ! -f "${file}" ]]; then
        log_error "File not found for MD5 hashing: ${file}"
        return 1
    fi

    _hash_with_cmd "${SENTINEL_MD5_CMD}" "${file}"
}

hash_sha1() {
    local -r file="${1}"

    if [[ ! -f "${file}" ]]; then
        log_error "File not found for SHA1 hashing: ${file}"
        return 1
    fi

    _hash_with_cmd "${SENTINEL_SHA1_CMD}" "${file}"
}

hash_sha256() {
    local -r file="${1}"

    if [[ ! -f "${file}" ]]; then
        log_error "File not found for SHA256 hashing: ${file}"
        return 1
    fi

    _hash_with_cmd "${SENTINEL_SHA256_CMD}" "${file}"
}

hash_sha512() {
    local -r file="${1}"

    if [[ ! -f "${file}" ]]; then
        log_error "File not found for SHA512 hashing: ${file}"
        return 1
    fi

    _hash_with_cmd "${SENTINEL_SHA512_CMD}" "${file}"
}

hash_file() {
    local -r file="${1}"
    local -r algorithm="${2:-sha256}"

    if [[ ! -f "${file}" ]]; then
        log_error "File not found for hashing: ${file}"
        return 1
    fi

    case "${algorithm,,}" in
        md5)
            hash_md5 "${file}"
            ;;
        sha1)
            hash_sha1 "${file}"
            ;;
        sha256)
            hash_sha256 "${file}"
            ;;
        sha512)
            hash_sha512 "${file}"
            ;;
        *)
            log_error "Unsupported hash algorithm: ${algorithm}"
            return 1
            ;;
    esac
}

hash_string() {
    local -r string="${1}"
    local -r algorithm="${2:-sha256}"

    local cmd=""

    case "${algorithm,,}" in
        md5)
            cmd="${SENTINEL_MD5_CMD}"
            ;;
        sha1)
            cmd="${SENTINEL_SHA1_CMD}"
            ;;
        sha256)
            cmd="${SENTINEL_SHA256_CMD}"
            ;;
        sha512)
            cmd="${SENTINEL_SHA512_CMD}"
            ;;
        *)
            log_error "Unsupported hash algorithm: ${algorithm}"
            return 1
            ;;
    esac

    _hash_string_with_cmd "${cmd}" "${string}"
}

verify_checksum() {
    local -r file="${1}"
    local -r expected_hash="${2}"
    local -r algorithm="${3:-sha256}"

    if [[ ! -f "${file}" ]]; then
        log_error "File not found for verification: ${file}"
        return 1
    fi

    local actual_hash
    actual_hash="$(hash_file "${file}" "${algorithm}")"

    if [[ "${actual_hash}" == "${expected_hash}" ]]; then
        log_debug "Checksum verified for ${file} (${algorithm})"
        return 0
    else
        log_warning "Checksum mismatch for ${file}: expected ${expected_hash}, got ${actual_hash}"
        return 1
    fi
}

hash_directory() {
    local -r dir="${1}"
    local -r algorithm="${2:-sha256}"

    if [[ ! -d "${dir}" ]]; then
        log_error "Directory not found for hashing: ${dir}"
        return 1
    fi

    local file
    local hash

    while IFS= read -r -d '' file; do
        hash="$(hash_file "${file}" "${algorithm}" 2>/dev/null)" || continue
        printf '%s  %s\n' "${hash}" "${file}"
    done < <(find "${dir}" -type f -print0 2>/dev/null | sort -z)
}

hash_directory_manifest() {
    local -r dir="${1}"
    local -r algorithm="${2:-sha256}"
    local -r output_file="${3:-}"

    local result
    result="$(hash_directory "${dir}" "${algorithm}")"

    if [[ -n "${output_file}" ]]; then
        printf '%s\n' "${result}" > "${output_file}"
        log_info "Directory manifest written to ${output_file}"
    else
        printf '%s\n' "${result}"
    fi
}
