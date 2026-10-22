# Embedded by the macOS updater. All values arrive as positional arguments;
# no paths or process metadata are inserted into shell source.
i=0
while [ "$(/bin/ps -p "$1" -o lstart=)" = "$2" ]; do
    [ "$i" -ge "$4" ] && exit 75
    /bin/sleep 1
    i=$((i+1))
done
exec /usr/bin/open -n -a "$3" --args --tray
