#!/usr/bin/env bash
set -ex
START_COMMAND="google-chrome"
PGREP="chrome"
MAXIMIZE="true"
DEFAULT_ARGS=""
EXTENSION_ARGS=""
EXTENSION_SRC_DIR="${EXTENSION_SRC_DIR:-/opt/proxylogin/extension}"
EXTENSION_WORK_DIR="${EXTENSION_WORK_DIR:-/tmp/proxylogin-extension}"
EXTENSION_COMPAT_FLAG="${EXTENSION_COMPAT_FLAG:---disable-features=DisableLoadExtensionCommandLineSwitch}"

has_switch() {
    case " $1 " in
        *" --$2="*|*" --$2 "*) return 0 ;;
        *) return 1 ;;
    esac
}

prepare_extension() {
    if [ ! -d "$EXTENSION_SRC_DIR" ] ; then
        echo "Extension directory not found: $EXTENSION_SRC_DIR"
        return
    fi

    rm -rf "$EXTENSION_WORK_DIR"
    mkdir -p "$EXTENSION_WORK_DIR"
    cp -a "$EXTENSION_SRC_DIR/." "$EXTENSION_WORK_DIR/"

    if [ -f "$EXTENSION_WORK_DIR/rules.json" ] ; then
        token_escaped=$(printf '%s' "${SEOCROMOM_TOKEN:-}" | sed 's/[\\/&]/\\&/g')
        sed -i "s/SEOCROMOM_TOKEN/${token_escaped}/g" "$EXTENSION_WORK_DIR/rules.json"
    fi

    extension_list="$EXTENSION_WORK_DIR"
    EXTENSION_ARGS=" --load-extension=$extension_list"
    EXTENSION_ARGS=" --disable-extensions-except=$extension_list$EXTENSION_ARGS"
}

prepare_extension
DEFAULT_ARGS+=" --start-maximized"
if [ -n "$PROXY_URL" ] ; then
    DEFAULT_ARGS+=" --proxy-server=$PROXY_URL"
fi
if [ -n "$EXTENSION_ARGS" ] ; then
    if [ -n "$EXTENSION_COMPAT_FLAG" ] ; then
        DEFAULT_ARGS+=" $EXTENSION_COMPAT_FLAG"
    fi
    DEFAULT_ARGS+="$EXTENSION_ARGS"
fi

ARGS="$DEFAULT_ARGS"
if [ -n "${APP_ARGS:-}" ] ; then
    ARGS="$APP_ARGS"

    if [ -n "$PROXY_URL" ] && ! has_switch "$ARGS" "proxy-server" ; then
        ARGS+=" --proxy-server=$PROXY_URL"
    fi

    if [ -n "$EXTENSION_ARGS" ] ; then
        if [ -n "$EXTENSION_COMPAT_FLAG" ] && ! has_switch "$ARGS" "disable-features" ; then
            ARGS+=" $EXTENSION_COMPAT_FLAG"
        fi
        if ! has_switch "$ARGS" "load-extension" ; then
            ARGS+="$EXTENSION_ARGS"
        fi
    fi
fi

options=$(getopt -o gau: -l go,assign,url: -n "$0" -- "$@") || exit
eval set -- "$options"

while [[ $1 != -- ]]; do
    case $1 in
        -g|--go) GO='true'; shift 1;;
        -a|--assign) ASSIGN='true'; shift 1;;
        -u|--url) OPT_URL=$2; shift 2;;
        *) echo "bad option: $1" >&2; exit 1;;
    esac
done
shift

# Process non-option arguments.
for arg; do
    echo "arg! $arg"
done

FORCE=$2

kasm_exec() {
    if [ -n "$OPT_URL" ] ; then
        URL=$OPT_URL
    elif [ -n "$1" ] ; then
        URL=$1
    fi 
    
    # Since we are execing into a container that already has the browser running from startup, 
    #  when we don't have a URL to open we want to do nothing. Otherwise a second browser instance would open. 
    if [ -n "$URL" ] ; then
        /usr/bin/filter_ready
        /usr/bin/desktop_ready
        $START_COMMAND $ARGS $OPT_URL
    else
        echo "No URL specified for exec command. Doing nothing."
    fi
}

kasm_startup() {
    if [ -n "$KASM_URL" ] ; then
        URL=$KASM_URL
    elif [ -z "$URL" ] ; then
        URL=$LAUNCH_URL
    fi

    

    if [ -z "$DISABLE_CUSTOM_STARTUP" ] ||  [ -n "$FORCE" ] ; then

        echo "Entering process startup loop"
        set +x
        while true
        do
            if ! pgrep -x $PGREP > /dev/null
            then
                /usr/bin/filter_ready
                /usr/bin/desktop_ready
                set +e
                $START_COMMAND $ARGS $URL
                set -e
            fi
            sleep 1
        done
        set -x
    
    fi

} 

if [ -n "$GO" ] || [ -n "$ASSIGN" ] ; then
    kasm_exec
else
    kasm_startup
fi
