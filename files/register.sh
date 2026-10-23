#!/bin/sh
# Registers the connector role with LoopProof: one HTTPS POST with curl, the registration token in the
# Authorization header. registration.tf runs it from the terraform_data resource, with:
#
#   LOOPPROOF_REGISTRATION_TOKEN   the token, from the ephemeral read of the tenant's parameter
#   LOOPPROOF_REGISTRATION_URL     where to POST
#   LOOPPROOF_REGISTRATION_BODY    {"role_arn": ..., "region": ...}, as JSON
#   LOOPPROOF_TOKEN_PARAMETER_ARN  the token's parameter, which the messages name
#   LOOPPROOF_ROLE_ARN             the messages give both, to paste into LoopProof instead
#   LOOPPROOF_REGION
#
# Terraform shows everything this script prints when it fails, so it never prints the token or the
# request: no set -x, no curl -v. The token reaches curl on its standard input, from printf, a shell
# builtin, so it is on no command line.
#
# It retries connection errors and 5xx answers, never a 4xx, which is LoopProof refusing the token.
# curl's own --retry isn't enough: it retries 408 and 429 too.

set -u

attempts=4

paste_instead() {
    printf '%s\n' \
        "Or paste the connector role ARN and the Region into LoopProof's onboarding:" \
        "Role ARN: $LOOPPROOF_ROLE_ARN" \
        "Region: $LOOPPROOF_REGION"
}

if ! command -v curl > /dev/null 2>&1; then
    printf '%s\n' \
        "The LoopProof connector registers the connector role with curl, which isn't on PATH." \
        "Install curl and apply again."
    paste_instead
    exit 1
fi

not_a_token() {
    printf '%s\n' \
        "The SSM parameter $LOOPPROOF_TOKEN_PARAMETER_ARN doesn't hold a registration token:" \
        "a token starts with \"lprt_\" and holds no spaces. Copy it from LoopProof's onboarding, and apply again."
    paste_instead
    exit 1
}

# The messages name the parameter, never what it holds.
case $LOOPPROOF_REGISTRATION_TOKEN in
    unset)
        printf '%s\n' \
            "The SSM parameter $LOOPPROOF_TOKEN_PARAMETER_ARN still holds the placeholder \"unset\"." \
            "Put the registration token from LoopProof's onboarding in it, and apply again."
        paste_instead
        exit 1
        ;;
    *[[:space:]]*) not_a_token ;;
    lprt_?*) ;;
    *) not_a_token ;;
esac

answer_file=
error_file=
trap 'rm -f "$answer_file" "$error_file"' EXIT
answer_file=$(mktemp) || exit 1
error_file=$(mktemp) || exit 1

attempt=1
delay=2
while :; do
    # curl prints the HTTP version and status, "0 000" without an answer, and writes the answer's body to
    # answer_file.
    status=$(
        printf 'Authorization: Bearer %s\n' "$LOOPPROOF_REGISTRATION_TOKEN" |
            curl -sS --fail-with-body --max-time 30 \
                --header @- \
                --header 'Content-Type: application/json' \
                --data-binary "$LOOPPROOF_REGISTRATION_BODY" \
                --output "$answer_file" \
                --write-out '%{http_version} %{http_code}' \
                "$LOOPPROOF_REGISTRATION_URL" 2> "$error_file"
    )
    curl_exit=$?
    # Nothing at all if curl couldn't start, which counts as no answer.
    code=${status##* }
    [ -n "$code" ] || code=000

    case $code in
        2??)
            printf 'LoopProof registered the connector role: HTTP/%s\n' "$status"
            cat "$answer_file"
            exit 0
            ;;
        4??)
            printf 'LoopProof refused the connector registration: HTTP/%s\n' "$status"
            printf "LoopProof's answer: "
            cat "$answer_file"
            printf '\n%s\n' \
                "Get a new registration token in LoopProof and put it in the SSM parameter" \
                "$LOOPPROOF_TOKEN_PARAMETER_ARN, then apply again."
            paste_instead
            exit 1
            ;;
        5??)
            failure="LoopProof's registration API answered HTTP/$status"
            ;;
        000)
            # No answer. Connection errors and timeouts are worth another attempt; anything else, such as a
            # certificate curl doesn't trust, isn't.
            failure="LoopProof's registration API at $LOOPPROOF_REGISTRATION_URL didn't answer: $(cat "$error_file")"
            case $curl_exit in
                5 | 6 | 7 | 28 | 35 | 52 | 55 | 56) ;;
                *)
                    printf '%s\n' "$failure"
                    paste_instead
                    exit 1
                    ;;
            esac
            ;;
        *)
            printf "LoopProof's registration API answered HTTP/%s, which the connector doesn't expect.\n" "$status"
            paste_instead
            exit 1
            ;;
    esac

    if [ "$attempt" -ge "$attempts" ]; then
        printf '%s, after %s attempts.\n' "$failure" "$attempts"
        if [ -s "$answer_file" ]; then
            printf "LoopProof's answer: "
            cat "$answer_file"
            printf '\n'
        fi
        printf '%s\n' "Apply again later."
        paste_instead
        exit 1
    fi
    sleep "$delay"
    attempt=$((attempt + 1))
    delay=$((delay * 2))
done
