#!/bin/sh
set -eu

cd "$(dirname "$0")/../.."
case "${1-}:$#" in
    :0|--preview:1|--check:1|--start-postgres:2) ;;
    *) printf '%s\n' 'Usage: sh frontend/tests/serve.sh [--check | --preview]' >&2; exit 1 ;;
esac
backend=${PATCHROCKET_FIXTURE_DB:-sqlite}
scenario=${PATCHROCKET_FIXTURE_SCENARIO:-default}
case "$backend" in
    sqlite) database_extension=pdo_sqlite ;;
    postgres) database_extension=pdo_pgsql ;;
    *) printf '%s\n' 'Choose sqlite or postgres for the browser fixture database.' >&2; exit 1 ;;
esac

if ! command -v php >/dev/null 2>&1; then
    printf '%s\n' 'The fixture dashboard needs PHP 8.2 or later on PATH.' >&2
    exit 1
fi
php -r '
    if (PHP_VERSION_ID < 80200) {
        fwrite(STDERR, "The fixture dashboard needs PHP 8.2 or later.\n");
        exit(1);
    }
    foreach ([$argv[1], "session", "xml"] as $extension) {
        if (!extension_loaded($extension)) {
            fwrite(STDERR, "Enable the PHP $extension extension to run the fixture dashboard.\n");
            exit(1);
        }
    }
' "$database_extension"
if [ ! -r vendor/autoload.php ]; then
    printf '%s\n' 'Install PHP dependencies with composer install before starting the fixture dashboard.' >&2
    exit 1
fi
postgres_image=postgres:16-alpine
if [ "$backend" = postgres ] && ! command -v docker >/dev/null 2>&1; then
    printf '%s\n' 'Install Docker to run the PostgreSQL browser fixtures.' >&2
    exit 1
fi

start_postgres() {
    cidfile=$1
    docker run --detach --cidfile "$cidfile" \
        --label com.patchrocket.fixture=browser \
        --publish 127.0.0.1::5432 --tmpfs /var/lib/postgresql/data \
        --env POSTGRES_PASSWORD --env POSTGRES_DB=patchrocket_fixture \
        "$postgres_image" >/dev/null
    container=$(cat "$cidfile")
    attempt=0
    until docker exec "$container" pg_isready -q -h 127.0.0.1 -U postgres -d patchrocket_fixture; do
        attempt=$((attempt + 1))
        if [ "$attempt" -ge 50 ]; then
            printf '%s\n' 'PostgreSQL did not start for the browser fixture.' >&2
            docker logs "$container" >&2
            return 1
        fi
        sleep 0.25
    done
    docker port "$container" 5432/tcp
}

if [ "${1-}" = '--start-postgres' ]; then
    start_postgres "$2"
    exit 0
fi
if [ "${1-}" = '--check' ]; then
    if [ "$backend" = postgres ] && ! docker image inspect "$postgres_image" >/dev/null 2>&1; then
        docker pull "$postgres_image"
    fi
    exit 0
fi
ui_dir=${PATCHROCKET_FIXTURE_UI_DIR:-"$PWD/public/ui"}
if [ ! -r "$ui_dir/index.html" ]; then
    printf '%s\n' 'Build the dashboard with npm ci and npm run build before starting the fixture dashboard.' >&2
    exit 1
fi

scratch=$(mktemp -d)
server_log=${PATCHROCKET_FIXTURE_SERVER_LOG:-"$scratch/server.log"}
startup_log=${PATCHROCKET_FIXTURE_STARTUP_LOG:-"$scratch/startup.log"}
server_pids=
pg_container=${PATCHROCKET_FIXTURE_PG_CONTAINER:-}
pg_database=
cleanup() {
    status=$?
    trap '' TERM INT
    for pid in $server_pids; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in $server_pids; do
        wait "$pid" 2>/dev/null || true
    done
    if [ -n "$pg_database" ] && [ -n "$pg_container" ]; then
        docker exec "$pg_container" dropdb --if-exists --force -U postgres "$pg_database" >/dev/null || status=1
    fi
    if [ -s "$scratch/postgres.cid" ]; then
        docker rm -f "$(cat "$scratch/postgres.cid")" >/dev/null || status=1
    fi
    rm -rf "$scratch/public" "$scratch/rollout-bin" "$scratch/cache"
    find "$scratch" -maxdepth 1 -type f -delete
    rmdir "$scratch"
    exit "$status"
}
trap cleanup EXIT
trap 'trap "" TERM INT; exit 0' TERM INT
printf 'Preparing the %s fixture for scenario %s.\n' "$backend" "$scenario" >"$startup_log"

mkdir "$scratch/public"
framed=false
if [ "${1-}" = '--preview' ] && [ "${PATCHROCKET_FIXTURE_FRAMED:-0}" = 1 ]; then
    framed=true
    export PATCHROCKET_FIXTURE_FRONT_CONTROLLER="$PWD/public/index.php"
    cp frontend/tests/preview-frame-controller.php "$scratch/public/index.php"
fi
for entry in "$PWD"/public/*; do
    case "${entry##*/}" in
        ui) continue ;;
        index.php) if [ "$framed" = true ]; then continue; fi ;;
    esac
    ln -s "$entry" "$scratch/public/"
done
ln -s "$ui_dir" "$scratch/public/ui"

export APP_ENV=test APP_DEBUG=1
export APP_SECRET="$(php -r 'echo bin2hex(random_bytes(32));')"
export PATCHROCKET_FIXTURE_CACHE_DIR="$scratch/cache"
export DASHBOARD_TRUSTED_HOSTS='^localhost$,^127\.0\.0\.1$,^\[::1\]$'
export DASHBOARD_TRUSTED_PROXIES=''
export AI_PROVIDER=off AI_OPENAI_KEY='' AI_ALLOW_CLOUD_SOURCE=0
unset SYMFONY_DOTENV_VARS

if [ "$backend" = postgres ]; then
    if [ -n "$pg_container" ]; then
        printf '%s\n' 'Creating an isolated database in the suite PostgreSQL container.' >>"$startup_log"
        pg_database="patchrocket_fixture_$(php -r 'echo bin2hex(random_bytes(12));')"
        docker exec "$pg_container" createdb -U postgres "$pg_database"
        pg_endpoint=$PATCHROCKET_FIXTURE_PG_ENDPOINT
        pg_password=$PATCHROCKET_FIXTURE_PG_PASSWORD
        pg_name=$pg_database
    else
        printf '%s\n' 'Starting a disposable PostgreSQL container.' >>"$startup_log"
        pg_password=$(php -r 'echo bin2hex(random_bytes(24));')
        pg_endpoint=$(POSTGRES_PASSWORD=$pg_password start_postgres "$scratch/postgres.cid")
        pg_name=patchrocket_fixture
    fi
    export DATABASE_URL="postgresql://postgres:$pg_password@$pg_endpoint/$pg_name?serverVersion=16"
    printf '%s\n' 'PostgreSQL is accepting connections.' >>"$startup_log"
else
    export DATABASE_URL="sqlite:///$scratch/dashboard.db"
fi

cat > "$scratch/vault" <<'SH'
#!/bin/sh
case "$*" in
    'kv get -mount=fixture -field=value fixture-managed-reference')
        printf '%s\n' '{"private_key":"-----BEGIN FIXTURE PRIVATE KEY-----\nfixture-secret-must-stay-server-side\n-----END FIXTURE PRIVATE KEY-----","known_hosts":"fixture-host-key"}'
        exit 0 ;;
    'kv get -mount=fixture -field=value fixture-git-reference')
        printf '%s\n' '{"repository":"https://git.example.invalid/team/repository","username":"fixture","token":"fixture-editor-git-token"}'
        exit 0 ;;
    'kv get -mount=fixture -field=value fixture-kubeconfig-reference')
        printf '%s\n' '{"kubeconfig":"{\"kind\":\"Config\",\"contexts\":[{\"name\":\"fixture-cluster\"}],\"clusters\":[{\"cluster\":{\"server\":\"https://cluster.example.invalid\"}}],\"users\":[{\"user\":{\"token\":\"fixture-editor-kube-token\"}}]}"}'
        exit 0 ;;
    'kv get -mount=fixture -field=value fixture-ansible-password')
        printf '%s\n' '{"password":"fixture-ansible-password"}'
        exit 0 ;;
    *fixture-rollout-pending) phase=pending ;;
    *fixture-rollout-ready) phase=ready ;;
    *fixture-rollout-unavailable) phase=unavailable ;;
    *) exit 1 ;;
esac
printf '%s\n' '{"kubeconfig":"{\"kind\":\"Config\",\"contexts\":[{\"name\":\"fixture-runtime\"}],\"current-context\":\"'"$phase"'\"}"}'
SH
cat > "$scratch/ansible-vault" <<'SH'
#!/bin/sh
set -eu
[ "$#" -eq 3 ] && [ "$1" = view ] || exit 1
case "$2" in --vault-password-file=*) ;; *) exit 1 ;; esac
[ "$(cat "${2#--vault-password-file=}")" = fixture-ansible-password ] || exit 1
[ "$(cat "$3")" = "$(printf '%s\n' '$ANSIBLE_VAULT;1.1;AES256' 'cafe8c564dd222bb')" ] || exit 1
printf '%s\n' 'ansible_ssh_private_key: fixture-ansible-private-key' 'ssh_known_hosts: fixture-ansible-known-hosts'
SH
cat > "$scratch/kubectl" <<'SH'
#!/bin/sh
set -eu
for arg; do
    case "$arg" in
        --kubeconfig=*) config=${arg#--kubeconfig=} ;;
        deployment|replicasets|pods) resource=$arg ;;
    esac
done
image="registry.example/web@sha256:$(printf '%064d' 1)"
case "$resource" in
    deployment)
        generation=2
        if grep -q '"current-context":"pending"' "$config"; then generation=1; fi
        printf '{"metadata":{"uid":"deployment","generation":2},"spec":{"replicas":1,"template":{"spec":{"containers":[{"name":"app","image":"%s"}]}}},"status":{"observedGeneration":%s,"availableReplicas":1}}' "$image" "$generation" ;;
    replicasets)
        if grep -q '"current-context":"unavailable"' "$config"; then
            printf '%s\n' 'Fixture kubectl stderr' >&2
            exit 1
        fi
        printf '%s' '{"items":[{"metadata":{"uid":"replica","ownerReferences":[{"uid":"deployment","controller":true}]}}]}' ;;
    pods)
        printf '{"items":[{"metadata":{"ownerReferences":[{"uid":"replica","controller":true}]},"status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}],"containerStatuses":[{"name":"app","ready":true,"state":{"running":{}},"imageID":"%s"}]}}]}' "$image" ;;
esac
SH
chmod 700 "$scratch/vault" "$scratch/ansible-vault" "$scratch/kubectl"
if [ "$scenario" = delivery-discovery ]; then
    cat > "$scratch/aws" <<'SH'
#!/bin/sh
set -eu
[ "$1 $3" = '--no-cli-pager --output=json' ] || exit 2
case "$2" in
    --region=eu-west-1) ;;
    --region=us-east-1) [ "$4" = sts ] || exit 3 ;;
    *) exit 2 ;;
esac
case "$4 $5" in
    'sts get-caller-identity') printf '%s\n' '{"Account":"012345678901"}' ;;
    'ecr describe-repositories')
        [ "$6" = --registry-id=012345678901 ] || exit 2
        printf '%s\n' '{"repositories":[{"repositoryUri":"012345678901.dkr.ecr.eu-west-1.amazonaws.com/fixture"}]}' ;;
    'eks list-clusters') exit 3 ;;
    'ec2 describe-instances') printf '%s\n' '{"Reservations":[]}' ;;
    *) exit 2 ;;
esac
SH
    chmod 700 "$scratch/aws"
fi
export PATH="$scratch:$PATH"

setup_step() {
    printf '%s\n' "$1" >>"$startup_log"
    shift
    "$@" >>"$startup_log" 2>&1
}
if ! (
    setup_step 'Installing the database schema.' php bin/console patchrocket:inventory init &&
    setup_step 'Recording the initial release poll.' php bin/console patchrocket:release track-due &&
    { [ "$scenario" = docker-scan-handoff ] || setup_step 'Recording the initial scan scheduler run.' php bin/console patchrocket:scan-schedule run-due; } &&
    setup_step 'Seeding the dashboard fixtures.' php frontend/tests/seed.php "$DATABASE_URL"
); then
    cat "$startup_log" >&2
    exit 1
fi
setup_code=
if [ "$scenario" = first-admin ]; then
    printf '%s\n' 'Issuing the fixture administrator setup code.' >>"$startup_log"
    if ! bootstrap_output=$(php bin/console patchrocket:auth bootstrap --no-ansi 2>>"$startup_log"); then
        printf '%s\n' "$bootstrap_output" >&2
        exit 1
    fi
    setup_code=$(printf '%s\n' "$bootstrap_output" | sed -n '/^[a-f0-9]\{40\}$/p')
    if [ -z "$setup_code" ]; then
        printf '%s\n' 'The fixture setup command returned no one-time code.' >&2
        exit 1
    fi
fi
server_path=$PATH
if [ "$scenario" = docker-rollout ]; then
    mkdir "$scratch/rollout-bin"
    cat > "$scratch/rollout-bin/docker" <<'SH'
#!/bin/sh
if [ "$*" = 'context show' ]; then
    printf '%s\n' 'fixture-docker'
    exit 0
fi
[ "${1:-}" = container ] && [ "${2:-}" = inspect ] || exit 1
for target; do :; done
case "$target" in
    fixture-previous) id=$(printf '%064d' 1); image=$(printf '%064d' 2) ;;
    fixture-replacement) id=$(printf '%064d' 3); image=$(printf '%064d' 4) ;;
    *) exit 1 ;;
esac
printf '{"id":"%s","name":"/%s","image":"sha256:%s","service":"fixture-web"}\n' "$id" "$target" "$image"
SH
    chmod 700 "$scratch/rollout-bin/docker"
    server_path="$scratch/rollout-bin:$server_path"
fi
start_server() {
    listen_log=$1
    printf '%s\n' 'Starting a PHP dashboard server on loopback.' >>"$startup_log"
    : >"$listen_log"
    # Browser cookies are shared across ports on the same host.
    session_cookie="PatchRocketFixture$(php -r 'echo bin2hex(random_bytes(8));')"
    PATH="$server_path" php -d session.save_path="$scratch" -d session.name="$session_cookie" \
        -S 127.0.0.1:0 -t "$scratch/public" >>"$listen_log" 2>&1 &
    listen_pid=$!
    server_pids="$server_pids $listen_pid"
    listen_url=
    attempt=0
    while [ "$attempt" -lt 100 ] && kill -0 "$listen_pid" 2>/dev/null; do
        listen_url=$(sed -n 's|.*Development Server (\(http://127\.0\.0\.1:[0-9][0-9]*\)) started.*|\1|p' "$listen_log")
        if [ -n "$listen_url" ]; then break; fi
        attempt=$((attempt + 1))
        sleep 0.05
    done
    if [ -z "$listen_url" ]; then
        printf '%s\n' 'The fixture dashboard could not start its loopback PHP server.' >&2
        cat "$listen_log" >&2
        return 1
    fi
    printf 'PHP dashboard ready at %s\n' "$listen_url" >>"$startup_log"
}

start_server "$server_log"
primary_pid=$listen_pid
url=$listen_url
compare_roles=false
if [ "${1-}" = '--preview' ] && [ "${PATCHROCKET_FIXTURE_COMPARE_ROLES:-0}" = 1 ]; then
    compare_roles=true
    start_server "$scratch/operator.log"
    operator_pid=$listen_pid
    operator_url=$listen_url
    start_server "$scratch/viewer.log"
    viewer_pid=$listen_pid
    viewer_url=$listen_url
fi

if [ -n "$setup_code" ]; then
    printf 'Fixture setup code: %s\n' "$setup_code"
fi
printf 'Fixture dashboard ready at %s\n' "$url"
if [ "${1-}" = '--preview' ]; then
    preview_path=${PATCHROCKET_FIXTURE_START_PATH:-/}
    if [ "$framed" = true ]; then
        preview_path=/ui/fixture-viewport.html
    elif [ "$scenario" = first-admin ]; then
        preview_path=${PATCHROCKET_FIXTURE_START_PATH:-/setup}
    fi
    if [ "$compare_roles" = true ]; then
        printf 'Administrator (fixture-admin) at %s%s\n' "$url" "$preview_path"
        printf 'Operator (fixture-operator) at %s%s\n' "$operator_url" "$preview_path"
        printf 'Viewer (fixture-viewer) at %s%s\n' "$viewer_url" "$preview_path"
        printf '%s\n' 'The password for all three fixture accounts is local-browser-test-only.'
    elif [ "$scenario" = first-admin ]; then
        printf 'Open scenario at %s%s\n' "$url" "$preview_path"
        printf '%s\n' 'Use the printed code to create the first administrator.'
    else
        if [ "$preview_path" != / ]; then
            printf 'Open scenario at %s%s\n' "$url" "$preview_path"
        fi
        if [ -n "${PATCHROCKET_FIXTURE_ACCOUNT:-}" ]; then
            printf 'Sign in as %s with password local-browser-test-only.\n' "$PATCHROCKET_FIXTURE_ACCOUNT"
        else
            printf '%s\n' 'Sign in as fixture-admin, fixture-operator, or fixture-viewer with password local-browser-test-only.'
        fi
    fi
    printf '%s\n' 'Press Ctrl+C to stop the server and discard the fixture data.'
fi
if [ "$compare_roles" = true ]; then
    while kill -0 "$primary_pid" "$operator_pid" "$viewer_pid" 2>/dev/null; do
        sleep 1
    done
    printf '%s\n' 'A role preview server stopped.' >&2
    cat "$server_log" "$scratch/operator.log" "$scratch/viewer.log" >&2
    exit 1
fi
if ! wait "$primary_pid"; then
    cat "$server_log" >&2
    exit 1
fi
