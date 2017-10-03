#!/bin/bash -

# csman.sh

PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
\export PATH
\unalias -a
hash -r
ulimit -H -c 0 --
IFS=$' \t\n'

set -eu -o pipefail

if [ "$#" -gt "0" ]; then
    if [ $(id -u) != "0" ]; then
        case "${1:-}" in
            cp|rsync|dc|dcq|d|disk|disks|e|embed|ex|extract)
            ;;
            *)
                #(>&2 echo "! needs sudo")
                #exit 1
                #pass="$(zenity --password --title='Sudo Password' 2> /dev/null)"
                #exec echo "$pass" | sudo -S "$0" "$@"
                exec /usr/bin/sudo -S "$0" "$@"
                exit $?
            ;;
        esac
    fi
fi

user="${SUDO_USER:-$(whoami)}"
toolsDir="$(dirname $0)"
csmkeyTool="${toolsDir}/cskey.sh"
lastName=""
lastContainer=""
lastContainerTime=""
lastSecret=""
lastSecretTime=""
csOptions=()
csiOptions=()
ckOptions=()
ckOptions2=()
csmCleanScreen="1"
csmName=""
csmLive="0"
mkfsOptions=()
csmChain="1"
csmMount="1"
cmsMountReadOnly="0"
cmsMountExec="0"
csmListShowKey="0"
csmCreateOverwriteOnly="0"
csmOpenDiskLabel=""
csmFileCheckFreeSpace="1"
embedSlot="1"
csmOutFile=""
slotCount=""
csmSecretFile=""
csmSecretFiles=()
slotOffsetFactor="2"

########################################################################

currentScriptPid=$$
function failed()
{
    kill -9 "$currentScriptPid"
}

function log()
{
    set +e
    echo "$@"
    set -e
}

function logError()
{
    (>&2 echo "$@")
}

# error
function onFailed()
{
    logError "!" "$@"
    failed
}

# value valueName
function checkArg()
{
    if [ -z "$1" ]; then
        onFailed "required ${2:-}"
    fi
}

# size
function checkNumber()
{
    local re='^[0-9]+$'
    if ! [[ "$1" =~ $re ]] ; then
        onFailed "$1 not a number"
    fi
}

function clearScreen()
{
    if [ "$csmCleanScreen" = "1" ]; then
        tput reset
    fi
}

########################################################################

# file
function ownFile()
{
    if [ -f "${1:-}" ]; then
        chown $(id -un "$user"):$(id -gn "$user") -- "$1"
    fi
}

# fileOrDir
function touchDiskFile()
{
    file="${1:-}"
    checkArg "$file" "fileOrDir"
    local time="${2:-}"
    if [ -z "$time" ]; then
        time=$(stat -c %z "$file")
    fi
    echo "Setting file times to: $time"
    if [ -f "$file" ]; then
        ownFile "$file"
        touchFile "$file" "$time"
        stat "$file"
    elif [ -d "$file" ]; then
        find "$file" -type f | while IFS=$'\n' read -r f; do
            echo " $f"
            ownFile "$f"
            touchFile "$f" "$time"
        done
    else
        onFailed "not found: $file"
    fi
    echo "Done"
}

# file time
function touchFile()
{
    local file="$1"
    local fileTime="${2:-}"
    if [ -f "$file" ]; then
        if [ -z "${fileTime}" ]; then
            if [ -d "/usr" ]; then
                fileTime=$(stat -c %z "/usr")
            else
                fileTime=$(stat -c %z -- "$HOME")
            fi
        fi
        set +e
        #sudo bash -s "$file" "$fileTime" <<-'EOF'
            now=$(date +"%F %T.%N %z") && date -s "${fileTime}" > /dev/null && touch -- "$file" 2> /dev/null
            date -s "$now" > /dev/null
        #   EOF
        set -e
    fi
}

function resetTime()
{
    touchFile "$lastContainer" "$lastContainerTime"
    touchFile "$lastSecret" "$lastSecretTime"
}

########################################################################

function newName()
{
    local newName=""
    while :
    do
        #a-zA-Z0-9
        newName=$(cat /dev/urandom | tr -dc '[:lower:]' | fold -w 3 | head -n1)
        if [ ! -e "/dev/mapper/${newName}" ]; then
            break
        fi
    done
    echo "$newName"
}

# name
function validName()
{
    local name="${1:-}"
    checkArg "$name" "name"
    if [ "$name" = "-" ]; then
        name="$(newName)"
    fi
    if [[ "$name" != csm-* ]]; then
        name="csm-${name}"
    fi
    name="${name//[^[:lower:][:upper:][:digit:]-]/}"
    checkArg "$name" "name"
    echo "$name"
}

# name
function innerName()
{
    echo "${1}_"
}

# name 1
function getDevice()
{
    local name="$1"
    # inner
    if [ "${2:-}" = "1" ]; then
        name="$(innerName "$name")"
    fi
    echo "/dev/mapper/$name"
}

function cleanMntDir()
{
    set +e
    rmdir "$HOME/mnt/tmpcsm" 2> /dev/null
    find "$HOME/mnt/" -maxdepth 1  -type d -name '?csm-*' -print0 | xargs -0 -r -n 1 -I {} rmdir {} 2> /dev/null
    set -e
}

# name
function mntDirRoot()
{
    echo "$HOME/mnt/${1}"
}

# name
function mntDirUser()
{
    echo "$HOME/mnt/u${1}"
}

########################################################################

# name
function umountContainer()
{
    local name=$(validName "${1:-}")
    local mntDir1=$(mntDirRoot "$name")
    local mntDir2=$(mntDirUser "$name")
    local lastError=""
    
    if [ -d "$mntDir2" ]; then
        set +e
        mountpoint "${mntDir2}" &>/dev/null
        lastError="$?"
        set +e
        if [ "${lastError}" = "0" ]; then
            set +e
            fuser -km "${mntDir2}"
            set -e
            sleep 1
            umount "${mntDir2}" && rmdir "${mntDir2}"
        else
            rmdir "${mntDir2}"
        fi
    fi
    if [ -d "$mntDir1" ]; then
        set +e
        mountpoint "${mntDir1}" &>/dev/null
        lastError="$?"
        set +e
        if [ "${lastError}" = "0" ]; then
            set +e
            fuser -km "${mntDir1}"
            set -e
            sleep 1
            set +e
            umount "${mntDir1}" && rmdir "${mntDir1}"
            set -e
        else
            set +e
            rmdir "${mntDir1}"
            set -e
        fi
    fi
}

# name
function mountContainer()
{
    local name=$(validName "${1:-}")
    local mntDir1=$(mntDirRoot "$name")
    local mntDir2=$(mntDirUser "$name")
    
    # check for inner one first
    local hasInner="1"
    local dev="$(getDevice "$name" "1")"
    if [ ! -e "$dev" ]; then
        hasInner="0"
        dev="$(getDevice "$name" "0")"
    fi
    if [ ! -e "$dev" ]; then
        onFailed "no mapper device: $name"
    fi
        
    local ro=""
    if [ "$cmsMountReadOnly" = "1" ]; then
        echo "# mounting read-only"
        ro="-o ro"
    fi
    local ex=""
    if [ "$cmsMountExec" = "1" ]; then
        echo "# mounting with exec option"
        ex="-o exec"
    fi
    
    mkdir -p "$mntDir1"
    set +e
    mount ${ro} -o users ${ex} "$dev" "$mntDir1"
    if [ "$?" != "0" ]; then
        closeContainerByName "$name"
        rmdir "$mntDir1"
        failed
    fi
    set -e
    set +e
    chown $(id -un "$user"):$(id -gn "$user") "$mntDir1" 2> /dev/null
    set -e
    #mkdir -p "$mntDir2"
    #bindfs ${ro} --multithreaded -u $(id -u "$user") -g $(id -g "$user") "$mntDir1" "$mntDir2"
    #echo "Mounted ${dev} at ${mntDir2}"
    echo "Mounted ${dev} at ${mntDir1}"
}

function closeContainerByName()
{
    local name=$(validName "${1:-}")
    
    local dev="$(getDevice "$name" "1")"
    if [ -e "$dev" ]; then
        if [ -z "$lastContainer" ]; then
            set +e
            lastContainer="$(getContainerFile "$name")"
            set -e
        fi
        cryptsetup close "$(innerName "$name")"
    fi
    dev="$(getDevice "$name" "0")"
    if [ -e "$dev" ]; then
        cryptsetup close "$name"
    fi
    resetTime
    log " Closed ${name} !"
}

# name
function closeContainer()
{
    local name=$(validName "${1:-}")
    log "Closing ${name} ..."
    umountContainer "$name"
    closeContainerByName "$name"
}

# list
function closeAll()
{
    for filename in /dev/mapper/*; do
        [ -e "$filename" ] || continue
        local name=$(basename -- "$filename")
        [ "$name" != "control" ] || continue
        [[ "$name" == csm-* ]] || continue
        [ "${name: -1}" != "_" ] || continue
        case "${1:-}" in
            1)
            listContainer "$name"
            log
            ;;
            2)
                if isSameContainerFile "$name" "${2:-}" ; then
                    csmIsContainerFileOpen="$name"
                    return
                fi
            ;;
            *)
            closeContainer "$name"
            ;;
        esac
    done
}

# file
csmIsContainerFileOpen=""
function isContainerFileOpen()
{
    csmIsContainerFileOpen=""
    closeAll 2 "$1"
}

# name file

function isSameContainerFile()
{
    local container="$(getContainerFile "$1")"
    if [ "$container" = "$2" ]; then
        return 0
    fi
    return 1
}

# name
function getContainerFile()
{
    local name=$(validName "${1:-}")
    #local f="$(cryptsetup status "$name" | grep loop: | cut -d ' ' -f 7)"
    set -- $(cryptsetup status "$name" | grep loop:)
    shift
    local f="$@"
    if [ -z "$f" ]; then
        #f="$(cryptsetup status csm-dwpi | grep device: | cut -d ' ' -f 5)"
        set -- $(cryptsetup status "$name" | grep device:)
        shift
        f="$@"
    fi
    echo "$f"
}

#dev
function getChipher()
{
    set -- $(cryptsetup status "$1" | grep cipher: )
    shift
    echo "$@"
}

function getMode()
{
    set -- $(cryptsetup status "$1" | grep mode:)
    shift
    echo "$@"
}

#dev
function getDmKey()
{
    #local k=$(dmsetup table --target crypt --showkey "${dev}" | cut -d ' ' -f 5)
    set -- $(dmsetup table --target crypt --showkey "$1")
    echo $5
}

function listContainer()
{
    local name=$(validName "${1:-}")
    local oName=${name:4}
    echo -e "Name:\t$oName\t$name"
    local container="$(getContainerFile "$name")"
    if [ -z "$container" ]; then
        return
    fi
    
    local mode="$(getMode "$name")"
    local cipher=""
    echo -e "File:\t$container\t$mode"
    local dev="$(getDevice "$name" "0")"
    local lastDev=""
    if [ -e "$dev" ]; then
        lastDev="$dev"
        time=$(stat -c %z "$dev")
        echo -e "Open:\t${time}"
        cipher="$(getChipher "$dev")"
        set +e
        local label="$(e2label "$dev" 2> /dev/null)"
        set -e
        echo -e "Device:\t${dev}\t${cipher}\t${label}"
        if [ "$csmListShowKey" = "1" ]; then
            local k=$(getDmKey "$dev")
            echo -e "RawKey:\t$k"
        fi
    fi
    dev="$(getDevice "$name" "1")"
    if [ -e "$dev" ]; then
        lastDev="$dev"
        cipher="$(getChipher "$dev")"
        set +e
        local label="$(e2label "$dev" 2> /dev/null)"
        set -e
        echo -e "Device:\t${dev}\t${cipher}\t${label:-<no label>}"
        if [ "$csmListShowKey" = "1" ]; then
            local k=$(getDmKey "$dev")
            echo -e "RawKey:\t$k"
        fi
    fi
    local mntDir1=$(mntDirRoot "$name")
    local mntDir2=$(mntDirUser "$name")
    if [ -d "$mntDir1" ]; then
        
        local m="$(mount | grep "$mntDir1")"
        if [ -n "$m" ]; then
            m="mounted"
        fi
        echo -e "Dir:\t$mntDir1\t$m\t$(stat -c "%U %G" "$mntDir1")"
    fi
    if [ -d "$mntDir2" ]; then
        local m="$(mount | grep "$mntDir2")"
        if [ -n "$m" ]; then
            m="mounted"
        fi
        echo -e "Dir:\t$mntDir2\t$m\t$(stat -c "%U %G" "$mntDir2")"
    fi
    if [ -n "$lastDev" ]; then
        set +e
        local df1=$(df --output=itotal,iused,iavail,ipcent "$lastDev" 2> /dev/null)
        local df2=$(df --output=size,used,avail,pcent -h "$lastDev" 2> /dev/null)
        set -e
        if [ -n "$df1" ] || [ -n "$df2" ]; then
            echo -e "Usage:\t$lastDev :"
            echo -e "$df1\n$df2" | column -t
        fi
    fi
}

########################################################################

function getVolumeDefaultLabel()
{
    if [ -f "${1:-}" ]; then
        echo -n "$(basename -- "$1")" | tr -s [:space:] | tr [:space:] '_'
    fi
}

function umountDevice()
{
    local device="$1"
    if [ -b "${device}" ]; then
        set +e
        ls ${device}?* 2>/dev/null | xargs -r -n 1 -I {} fuser -km {}
        ls ${device}?* 2>/dev/null | xargs -r -n 1 umount
        set -e
    fi
}

# dev container
function setVolumeLabel()
{
    local lastDev="$1"
    local device="$2"
    # set default label if volume has no label, may fail if no FS
    if [ -n "$lastDev" ]; then
        local label=""
        if [ -n "${csmOpenDiskLabel}" ]; then
            set +e
            e2label "$lastDev" "${csmOpenDiskLabel}"
            set -e
        else
            set +e
            label="$(e2label "$lastDev" 2> /dev/null)"
            set -e
            if [ -z "$label" ] && [ -f "$device" ]; then
                label=$(getVolumeDefaultLabel "$device")
                if [ -n "$label" ]; then
                    set +e
                    e2label "$lastDev" "$label" 2> /dev/null
                    set -e
                fi
            fi
        fi
        
        set +e
        label="$(e2label "$lastDev" 2> /dev/null)"
        set -e
        if [ -n "$label" ]; then
            echo "# label: $label"
        fi
    fi
}

#key name device
function openContainerByName()
{
    local key="$1"
    local name="$2"
    local device="$3"
    
    umountDevice "${device}"
    
    local cro=""
    if [ "$cmsMountReadOnly" = "1" ]; then
        echo "# opening read-only"
        cro="--readonly"
    fi
    
    local dev="$(getDevice "$name" "0")"
    echo "Opening ${dev} ..."
    echo -n "$key" | base64 -d | cryptsetup --type plain -c aes-xts-plain64 -s 512 -h sha512 --shared $cro "${csOptions[@]}" open "${device}" "${name}" -
    cryptsetup status "${dev}"
    local lastDev="${dev}"
    
    if [ "$csmChain" = "1" ]; then
        local name1="$(innerName "$name")"
        local dev1="$(getDevice "$name" "1")"
        echo "Opening ${dev1} ..."
        set +e
        echo -n "${key}" | base64 -d | cat - <(echo -n "different key") | cryptsetup --type plain -c twofish-cbc-essiv:sha256 -s 256 -h sha512 $cro "${csiOptions[@]}" open "${dev}" "${name1}" -
        if [ "$?" != "0" ]; then
            closeContainerByName "$name"
            failed
        fi
        set -e
        cryptsetup status "${dev1}"
        lastDev="${dev1}"
    fi
    
    setVolumeLabel "$lastDev" "$device"
}

# name container rest
function openContainer()
{
    local name=$(validName "${1:-}")
    lastName="$name"
    local oName=${name:4}
    shift

    local device="${1:-}"
    if [ "${device}" = "?" ]; then
        read -e -p "Container file (or Enter if none): " device
        logError
    elif [ "${device}" = "!" ]; then
        device="$(zenity --file-selection --title='Select Container File' 2> /dev/null)"
    fi

    checkArg "$device" "container"
    lastContainer="$device"
    if [ -f "$device" ]; then
        lastContainerTime=$(stat -c %z "$device")
    fi
    if [ ! -e "$device" ]; then
        resetTime
        onFailed "cannot open: $device"
    fi
    shift
    
    isContainerFileOpen "$device"
    if [ -n "$csmIsContainerFileOpen" ]; then
        listContainer ${csmIsContainerFileOpen}
        logError
        onFailed "${device} is already open (${csmIsContainerFileOpen})"
    fi
    
    #local secret="${1:-}"
    #checkArg "$secret" "secret"
    #shift
    
    processOptions "$@"
    local secret="$csmSecretFile"
    if [ -z "$secret" ]; then
        secret="$device"
    fi
    checkArg "$secret" "-s secret"
    
    if [ -n "$csmName" ]; then
        name=$(validName "${csmName}")
        lastName="$name"
        oName=${name:4}
    fi
    
    echo "Reading ${device} secret from (${secret}) using ($name)"
    local key=$("${csmkeyTool}" dec "$secret" "${ckOptions[@]}" | base64 -w 0)
    if [ -z "$key" ]; then
        resetTime
        onFailed "cannot get secret"
    fi
    #touchFile "$lastSecret" "$lastSecretTime"
    clearScreen
    openContainerByName "$key" "$name" "$device"
    
    if [ "$csmMount" = "1" ]; then
        mountContainer "$name"
    fi
    echo "To close use:"
    echo "$(basename -- "$0") close ${oName}"
    echo "$(basename -- "$0") closeAll"    
}

########################################################################

function testRndDataSource()
{
    openssl enc -aes-256-ctr -pass pass:"test" -nosalt < <(echo -n "test") > /dev/null 2>/dev/null
}

function rndDataSource()
{
    # https://unix.stackexchange.com/questions/248235/always-error-writing-output-file-in-openssl
    testRndDataSource
    # https://wiki.archlinux.org/index.php/Securely_wipe_disk/Tips_and_tricks#dd_-_advanced_example
    local tpass=$(tr -cd '[:alnum:]' < /dev/urandom | head -c128)
    set +e
    openssl enc -aes-256-ctr -pass pass:"$tpass" -nosalt </dev/zero 2>/dev/null
    set -e
}

# file
function createDir()
{
    local file="$1"
    if [ -S "${file}" ]; then
        return
    fi
    local dir=$(dirname -- "${file}")
    if [ dir != "." ]; then
        mkdir -p -- "${dir}"
    fi
}

# container bs count seek
function ddContainer()
{
    local container="$1"
    local bs="$2"
    local count="$3"
    local seek="${4:-}"

    if [ -z "$seek" ]; then
        time rndDataSource | dd iflag=fullblock of="$container" bs="$bs" count="$count" status=progress conv=fdatasync
        #sudo -u "$user" dd iflag=fullblock if=/dev/urandom of="$container" bs="$bs" count="$count" status=progress
    else
        #sudo -u "$user" dd iflag=fullblock if=/dev/urandom of="$container" bs="$bs" count="$count" seek="$seek" status=progress
        time rndDataSource | dd iflag=fullblock of="$container" bs="$bs" count="$count" seek="$seek" status=progress conv=fdatasync
    fi
    sleep 1
    #sync -f "$container"
}

# secret
function createSecret()
{
    local secret="$1"
    if [ "${secret}" = "--" ]; then
        return
    fi
    echo "Creating ${secret} ..."
    "${csmkeyTool}" enc "$secret" "${ckOptions[@]}"
    ownFile "$secret"
}

function checkFreeSpace()
{
    if [ "${csmFileCheckFreeSpace}" != "1" ]; then
        return
    fi
    local size="$1"
    local sizeNum="$2"
    local dir="$(dirname -- "$(realpath -- "${container}")")"
    local availMb=$(df --block-size=1 --output=avail "${dir}" | tail -n 1)
    availMb=$((availMb / 1024 / 1024))
    if [ "${size: -1}" = "G" ]; then
        availMb=$((availMb / 1024)) #gb
    fi
    if (( sizeNum > availMb )); then
        onFailed "${sizeNum}${size: -1} is bigger than free space ${availMb}${size: -1} in ${dir}"
    fi
}

function getDeviceSize()
{
    local size=$(blockdev --getsize64 "$1")
    size=$((size / 1024 / 1024)) # MB
    if (( size > 1024 )); then
        echo -n "$((size / 1024))G"
    else
        echo -n "${size}M"
    fi
}

# name secret container size rest
function createContainer()
{
    local name=$(validName "-")
        
    local container="${1:-}"
    checkArg "$container" "container"
    shift
    
    #local secret="${1:-}"
    #checkArg "$secret" "secret"
    #shift

    local size="${1:-}"
    checkArg "$size" "size"
    shift

    local sizeNum="${size: : -1}"
    checkNumber "$sizeNum"
    
    local blockDevice="0"
    local writeContainer="1"
    local overwriteContainer=""
    if [ -f "$container" ]; then
        echo "Container file exists: $(ls -sh "${container}")"
        read -p "Overwrite? [y (overwrite) | e (create filesystem only) | Enter to exit]: " overwriteContainer
        if [ "$overwriteContainer" = "y" ]; then
            writeContainer="1"
        elif [ "$overwriteContainer" = "e" ]; then
            writeContainer="0"
        else
            onFailed "nothing to do"
        fi
    fi
    if [ -b "$container" ]; then
        if [ "$sizeNum" -gt 0 ]; then
            onFailed "Invalid size: ${size} (use 0G)"
        fi
        blockDevice="1"
        local bSize=$(getDeviceSize "${container}")
        echo "Are you sure to encrypt block device: ${bSize} ${container}"
        echo "Size parameter will be ingored for block devices"
        read -p "Overwrite? [y (overwrite) | e (create filesystem only) | Enter to exit]: " overwriteContainer
        if [ "$overwriteContainer" = "y" ]; then
            writeContainer="1"
        elif [ "$overwriteContainer" = "e" ]; then
            writeContainer="0"
        else
            onFailed "nothing to do"
        fi
    fi
    
    processOptions "$@"
    
    local secret="$csmSecretFile"
    checkArg "$secret" "-s secret"
    
    if [ "${csmCreateOverwriteOnly}" = "1" ]; then
        echo "# mode: overwrite only"
    fi
    
    if [ "$writeContainer" = "1" ]; then
        if [ "$blockDevice" = "1" ]; then
            umountDevice "${container}"
            testRndDataSource
            echo "Overwriting block device: ${container} ..."
            #hmm, we have to ingore errors here
            echo "# info: script will go on in case of errors here, read the output and decide if all ok ..."
            echo "# info: when done, it is ok to see: dd: error writing '${container}': No space left on device"
            set +e
            time rndDataSource | dd iflag=fullblock of="$container" bs=1M status=progress
            set -e
            echo "# info: sync data, this may take a while if other write operations are running ..."
            sync
        else
            if [ "$sizeNum" -le 0 ]; then
                onFailed "Invalid size: ${size}"
            fi
            
            checkFreeSpace "${size}" "${sizeNum}"
    
            echo "Creating ${container} with ${sizeNum}${size: -1} ..."
            createDir "${container}"
            if [ "${size: -1}" = "G" ]; then
                ddContainer "$container" "1G" "$sizeNum"
            elif [ "${size: -1}" = "M" ]; then
                ddContainer "$container" "1M" "$sizeNum"
            else
                onFailed "size can be M or G"
            fi
            ownFile "$container"
        fi
    else
        echo "Reusing existing data (size ${size} will be ingored): $container"
    fi
    
    if [ "${csmCreateOverwriteOnly}" = "1" ]; then
        echo "# mode: overwrite only: done"
        return
    fi
    
    if [ -f "$secret" ] && [ "$secret" != "--" ]; then
        lastSecret="$secret"
        lastSecretTime=$(stat -c %z "$secret")
        read -p "Overwrite secret file $secret [y | Enter to reuse]: " overwriteSecret
        case "$overwriteSecret" in
            y)
            createSecret "$secret"
            ;;
        esac
    else
        createSecret "$secret"
    fi
    
    clearScreen
    
    echo "(Re-)enter password to open the container for formating (existing data, if any, will be lost) ..."
    local key=$("${csmkeyTool}" dec "$secret" "${ckOptions[@]}" | base64 -w 0)
    if [ -z "$key" ]; then
        onFailed "cannot get secret"
    fi

    clearScreen
    touchFile "$lastSecret" "$lastSecretTime"
    openContainerByName "$key" "$name" "$container"
    
    local dev="$(getDevice "$name" "1")"
    if [ ! -e "$dev" ]; then
        dev="$(getDevice "$name" "0")"
    fi
    if [ ! -e "$dev" ]; then
        onFailed "cannot find: $dev"
    fi

    echo "Creating filesystem in $dev ..."
    mkfs -t ext4 -m 0 "${mkfsOptions[@]}" "$dev"
    echo "Created file system."
    sleep 1
    closeContainerByName "$name"
    
    if [ -n "$secret" ] && [ "$secret" != "--" ] && [ -f "$secret" ] && [ -n "$slotCount" ] && [ "$slotCount" -gt "0" ]; then
        embedSecretOnCreate "${secret}" "1" "${container}"
        embedSecretOnCreate "${secret}.01" "2" "${container}"
        embedSecretOnCreate "${secret}.02" "3" "${container}"
        embedSecretOnCreate "${secret}.03" "4" "${container}"
        echo
    fi
    
    echo "Done! To open container use:"
    echo "$(basename -- "$0") open ${container} -s ${secret} (options)"
}

function embedSecretOnCreate()
{
    local secret="$1"
    local slot="$2"
    local container="$3"
    local check=$(("$slot"-1))
    
    if [ "$slotCount" -gt "$check" ] && [ -f "${secret}" ]; then
        echo "# Embedding ${secret} in slot ${slot}/${slotCount} of ${container} (${secret} file can be removed or backed-up manually)"
        embedSecretInSlot "$container" "$slot" "$secret"
        touchFile "${secret}" "$lastSecretTime"
    fi
}

########################################################################

# name
function resizeContainer()
{
    local name=$(validName "${1:-}")
    local dev="$(getDevice "$name" "0")"
    local lastDev=""
    if [ -e "$dev" ]; then
        lastDev="$dev"
        cryptsetup resize "$name"
    fi
    dev="$(getDevice "$name" "1")"
    if [ -e "$dev" ]; then
        lastDev="$dev"
        local iName="$(innerName "$name")"
        cryptsetup resize "${iName}"
    fi
    
    if [ -n "$lastDev" ]; then
        resize2fs "$lastDev"
    fi
}

# only works for full G/M blocks
function increaseContainer()
{
    local name=$(validName "${1:-}")
    shift
    local size="${1:-}"
    checkArg "$size" "size"
    shift
    local sizeNum="${size: : -1}"
    checkNumber "$sizeNum"

    container="$(getContainerFile "$name")"
    if [ ! -f "$container" ]; then
        onFailed "no such container file ${container}"
    fi
    local currentSize=$(stat -c "%s" "$container")
    if [ "${size: -1}" = "G" ]; then
        local sizeG=$(($currentSize / (1024 * 1024 * 1024)))
        if [ "$sizeG" = "0" ]; then # keep it simple
            onFailed "cannot determine current size in G"
        fi
        ddContainer "$container" "1G" "$sizeNum" "$sizeG"
    elif [ "${size: -1}" = "M" ]; then
        local sizeM=$(($currentSize / (1024 * 1024)))
        if [ "$sizeM" = "0" ]; then
            onFailed "cannot determine current size in M"
        fi
        ddContainer "$container" "1M" "$sizeNum" "$sizeM"
    else
        onFailed "size can be M or G"
    fi
    resizeContainer "$name"
}

########################################################################

# infile
function changePassword()
{
    local ifile="$1"
    shift
    processOptions "$@"
    local ofile="${csmOutFile}"
    checkArg "$ofile" "-out file"
    #if [ -z "$ofile" ]; then
    #    ofile="$ifile"
    #fi
    echo "# Decoding ${ifile} ..."
    local secret=$("${csmkeyTool}" dec "${ifile}" "${ckOptions[@]}" | base64 -w 0)
    if [ -z "${secret}" ]; then
        onFailed "cannot decode secret from ${ifile}"
    fi
    if (( ! ${#ckOptions2[@]} )); then
        echo "# using same options for encode"
        ckOptions2=( "${ckOptions[@]}" )
    fi
    "${csmkeyTool}" enc "${ofile}" -s <(echo -n "${secret}") "${ckOptions2[@]}"
}

########################################################################

# https://unix.stackexchange.com/questions/65077/is-it-possible-to-see-cp-speed-and-percent-copied
function copyDir()
{
    local src="${1:-}"
    local dst="${2:-}"
    checkArg "$src" "src"
    checkArg "$dst" "dstDir"

    local srcFull="$(realpath -- "${src}")"
    local srcParent="$(dirname -- "${srcFull}")"
    local srcDir="$(basename -- ${srcFull})"
    
    local totalSize="$( du -cs -BK --apparent-size "${src}" |
              tail -n 1 |
              cut -d "$(echo -e "\t")" -f 1)"
    local totalSizeNum=${totalSize::-1}          
    echo "Copy: ${srcFull}: ${totalSize} ~ $(( totalSizeNum / 1024 ))M ~ $(( totalSizeNum/1024/1024 ))G => $(realpath -- "${dst}")/${srcDir}"
    
    mkdir -p -- "${dst}"
    time tar -cf - -C "${srcParent}" "${srcDir}" |
        pv -s "${totalSize}" |
        ( cd -- "${dst}"; tar -xf - )
}

function rsyncDir()
{
    time rsync -ah --info=progress2 --no-i-r ${@%/}
}

########################################################################

dcDir=""
dcStart=$(date +%s)
dcShowInfo="1"

function dcCleanUp()
{
    local location="$dcDir"
    dcDir=""
    if [ -z "$location" ]; then
        return
    fi

    if [ -d "${location}" ]; then
        log " Removing: ${location}"
        rm -rf "${location}"
    fi
    end=$(date +%s)
    runtime=$((end-dcStart))
    log "Done: ${runtime} seconds"
    exit
}

function dcPrintAvailable {
    available=$(df -Ph "${dcDir}" | tail -1 | tr -s ' ' | cut -d ' ' -f 4)
    echo -n "$available"
}

function dcInfo()
{
    if [ "${dcShowInfo}" != "1" ]; then
        return
    fi
    cat <<EOF
# info: before running dc tool, call once manually on your partition:

  sudo tune2fs -m 0 $1
  sudo tune2fs -l $1 | grep 'Reserved block count'

# info: last command should return 0
EOF
    read -p "Press Enter to continue or Ctrl+C to exit: "
    echo
}

function dcCleanFreeDiskSpace()
{
    local count=0
    local location="${1:-}"
    if [ -n "$location" ]; then
        shift
        processOptions "$@"
    else
        location=.
    fi
    
    location="$(realpath -- "${location}")"
    location="${location}/csm-zero-tmp"
    if [ -d "${location}" ]; then
        if [ "${dcShowInfo}" = "1" ]; then
            echo "Temporary folder ${location} exits"
            read -p "Delete? [y] | [Enter to exit]: " deleteZeroTemp
            if [ "${deleteZeroTemp}" != "y" ]; then
                exit
            fi
        fi
        rm -rf -- "${location}"
    fi
    
    trap dcCleanUp 0 SIGHUP SIGINT SIGQUIT SIGTERM SIGABRT SIGQUIT 
    dcDir="${location}"
    mkdir -p "${dcDir}"
    local partition=$(df -P "${dcDir}" | tail -1 | tr -s ' ' | cut -d ' ' -f 1)
    dcInfo "${partition}"
    dcStart=$(date +%s)
    echo -e "Using folder ${dcDir}\nOverwriting free partition space in ${partition}"
    echo -e "May take some time. Press Ctrl+C to stop:\n\n"
   
    dcPrintAvailable
    while : ; do
        count=$((count+1))
        echo -n "+${count}"
        set +e
        dd if=/dev/zero iflag=fullblock count=1024 bs=1M conv=fdatasync >> "${dcDir}/zero.${count}" 2>/dev/null
        res=$?
        set -e
        if [ $res -ne 0 ]; then
            sync
            dcPrintAvailable
            break;
        fi
    done
    echo " "
    while : ; do
        count=$((count+1))
        set +e
        cat /dev/zero > "${dcDir}/zero.${count}" 2>/dev/null
        res=$?
        set -e
        if [ $res -ne 0 ]; then
            sync
            available=$(df -P "${dcDir}" | tail -1 | tr -s ' ' | cut -d ' ' -f 4)
            echo -n "$available"
            echo -n .
            if [[ $available -lt 5 ]] ; then
                break;
            fi
        fi
    done
    sleep 1 ; sync
    echo -e "\n"
    dcCleanUp
}

########################################################################

function embedSecret()
{
    local containerFile="$1"
    if [ ! -e "$containerFile" ]; then
        onFailed "container file required"
    fi
    shift
    
    processOptions "$@"
    local slot=${embedSlot:-1}
    #local secretFile="$csmSecretFile"

    local count="$slot"
    for secretFile in "${csmSecretFiles[@]}"; do
        embedSecretInSlot "$containerFile" "$count" "$secretFile"
        count=$((count+1))
    done
    log Done
}

# container slot secretFile
function embedSecretInSlot()
{
    local containerFile="$1"
    if [ ! -e "$containerFile" ]; then
        onFailed "container file required"
    fi
    local slot="$2"
    local seek=$(("$slot" - 1))
    local secretFile="$3"

    if [ "$secretFile" = "-" ]; then
        #log "Storing secret in slot ${slot} at byte offset $(("$seek" * 1024)) (cryptsetup -o $(("$seek" * "$slotOffsetFactor"))) of container ${containerFile}"
        cat - | dd status=none conv=notrunc bs=1024 count=1 seek="$seek" of="$containerFile" > /dev/null
        return
    fi
    
    if [ "$secretFile" = "*RANDOM*" ]; then
        log "Removing any secret in slot ${slot} at byte offset $(("$seek" * 1024)) (cryptsetup -o $(("$seek" * "$slotOffsetFactor"))) of container ${containerFile}"
        dd status=none conv=notrunc bs=1024 count=1 seek="$seek" if="/dev/urandom" of="$containerFile" > /dev/null
        return
    fi
    
    if [ ! -f "$secretFile" ]; then
        onFailed "-s secret file required"
    fi

    log "Storing secret ${secretFile} in slot ${slot} at byte offset $(("$seek" * 1024)) (cryptsetup -o $(("$seek" * "$slotOffsetFactor"))) of container ${containerFile}"
    dd status=none conv=notrunc bs=1024 count=1 seek="$seek" if="$secretFile" of="$containerFile" > /dev/null
}

function extractSecret()
{
    local containerFile="$1"
    if [ ! -e "$containerFile" ]; then
        onFailed "container file required"
    fi
    shift
    
    processOptions "$@"
    
    local slot=${embedSlot:-1}
    local skip=$(("$slot" - 1))
    local secretFile="$csmSecretFile"
    
    if [ "$secretFile" = "-" ]; then
        dd status=none bs=1024 count=1 skip="$skip" if="$containerFile"
        return
    fi
    
    if [ -z "$secretFile" ]; then
        onFailed "-s secret file required"
    fi

    log "Saving secret from slot ${slot} at byte offset $(("$skip" * 1024)) (cryptsetup -o $(("$skip" * "$slotOffsetFactor"))) to ${secretFile}"
    dd status=none bs=1024 count=1 skip="$skip" if="$containerFile" of="$secretFile" > /dev/null
    log Done
}

########################################################################

function cleanUp()
{
    local name="$lastName"
    lastName=""
    if [ -n "$name" ]; then
        set +e
        tput sgr 0
        echo
        set -e
        closeContainer "$name"
        exit 0
    fi
}

function showChecksum()
{
    local how=56
    sha256sum "$0" | tail -c +$how
    sha256sum "${csmkeyTool}" | tail -c +$how
    if [ -f "${toolsDir}/aes" ]; then
        sha256sum "${toolsDir}/aes" | tail -c +$how
    fi
    if [ -f "${toolsDir}/argon2" ]; then
        sha256sum "${toolsDir}/argon2" | tail -c +$how
    fi
    echo
} >&2

function showHelp()
{
    local bn=$(basename -- "$0")
    local kn=$(basename -- "${csmkeyTool}")
    cat << EOF
Usage:
 $bn open|o device -s secret [ openCreateOptions ]
   if device and / or secret are: ? read from command line, or ! zenity
   ol  is same as open ... -l
   olr is same as open -l -r
 $bn close|c name
 $bn closeAll|ca
 $bn list|l
 $bn mount|m name
 $bn umount|u name
 $bn create|n container size -s secret [ options ]
   size should end in M or G
 $bn resize|r name
 $bn increase|i name bySize
  bySize should end in M or G
 $bn touch|t fileOrDir [time]
   if set, time has to be in format: "$(date +"%F %T.%N %z")"
 $bn synctime|st
 $bn chp inFile [outFile] [ openCreateOptions ] : only -ck -cko are used
 $bn k ... : invoke $kn ...
 $bn cp src dstDir
   can be used without sudo, needs pv
 $bn rsync src dst
   can be used without sudo, needs rsync
 $bn dc dir
   can be used without sudo, default dir is .
   clean free disk space in partition having dir
 $bn d|disk|disks
   can be used without sudo, runs df and lsblk
 $bn e|embed device -s secret
   embed secret to device, if secret is - read from stdin
 $bn ex|extract device -s secret
   extract secret from device, if secret is - write to stdout
Where [ options ]:
 -s|-secret : (create|open|embed|extract) secret file
     for open if not set container file is used
     for embed can be repeated
 -co cryptsetup options --- : outer encryption layer
 -ci cryptsetup options --- : inner encryption layer
 -ck $kn options ---"
 -cko $kn options --- : only for use with chp output
 -cf mkfs ext4 options --- : (create)
 -l|-live : (open) live
 -n|-name name : (open) use csm-name
 -sl label : (open) set ext4 label
 -nocls : (open|create) do not clean screen after password entry
 -one : (open|create) use only one (outer) encryption layer
 -u : (open) do not mount on open
 -r|-ro : (open) mount user read-only
 -e|-exec : (open) mount with exec option (default no exec)
 -sfc : (create) skip free disk space check for files
 -oo : (create) dd only
 -lk : (list) list raw keys
 -sc|-slots slots : overwrites -co -o parameter (default 4, use 0 for no slots)
 -s0 : same as -slots 0
 -es|-slot slot : (embed|extract) slot to use (default 1)
 -d : (embed) delete slot, if used with -s deletes next slot
 -q : (dc) no startup information
 -out: (chp) output file
Example:
 sudo csmap.sh open container.bin -s secret.bin -l -ck -k -h -p 8 -m 14 -t 1000 -- ---

EOF
} >&2

function processOptions()
{
    while (( $# > 0 )); do
        local current="${1:-}"
        case "$current" in
            -co)
                shift
                csOptions=()
                while [ "${1:-}" != "---" ]; do
                    csOptions+=( "${1:-}" )
                    set +e
                    shift
                    if [ $? != 0 ]; then
                        onFailed "-co no ---"
                    fi
                    set -e
                done
            ;;
            -ci)
                shift
                csiOptions=()
                while [ "${1:-}" != "---" ]; do
                    csiOptions+=( "${1:-}" )
                    set +e
                    shift
                    if [ $? != 0 ]; then
                        onFailed "-ci no ---"
                    fi
                    set -e
                done
            ;;
            -ck)
                shift
                ckOptions=()
                while [ "${1:-}" != "---" ]; do
                    ckOptions+=( "${1:-}" )
                    set +e
                    shift
                    if [ $? != 0 ]; then
                        onFailed "-ck no ---"
                    fi
                    set -e
                done
            ;;
            -cko)
                shift
                ckOptions2=()
                while [ "${1:-}" != "---" ]; do
                    ckOptions2+=( "${1:-}" )
                    set +e
                    shift
                    if [ $? != 0 ]; then
                        onFailed "-cko no ---"
                    fi
                    set -e
                done
            ;;
            -cf)
                shift
                mkfsOptions=()
                while [ "${1:-}" != "---" ]; do
                    mkfsOptions+=( "${1:-}" )
                    set +e
                    shift
                    if [ $? != 0 ]; then
                        onFailed "-cf no ---"
                    fi
                    set -e
                done
            ;;
            -nocls)
                csmCleanScreen="0"
            ;;
            -n|-name)
                csmName="${2:-}"
                shift
            ;;
            -sl)
                csmOpenDiskLabel="${2:-}"
                shift
            ;;
            -es|-slot)
                embedSlot="${2:-?"! -slot number"}"
                shift
            ;;
            -sc|-slots)
                slotCount="${2:?"! -slots count"}"
                shift
            ;;
            -s0)
                slotCount="0"
            ;;
            -out)
                csmOutFile="${2:?"! -out outFile"}"
                shift
            ;;
            -s|-secret)
                csmSecretFile="${2:?"! -s secretFile"}"
                csmSecretFiles+=( "$csmSecretFile" )
                shift
            ;;
            -d)
                csmSecretFiles+=( "*RANDOM*" )
            ;;
            -l|-live)
                csmLive="1"
            ;;
            -one)
                csmChain="0"
            ;;
            -u)
                csmMount="0"
            ;;
            -r|-ro)
                cmsMountReadOnly="1"
            ;;
            -e|-exe|-exec)
                cmsMountExec="1"
            ;;  
            -lk)
                csmListShowKey="1"
            ;;
            -sfc)
                csmFileCheckFreeSpace="0"
            ;;
            -oo)
                csmCreateOverwriteOnly="1"
                csmSecretFile="!!any!!"
            ;;
            -q)
                dcShowInfo="0"
            ;;
            *)
                onFailed "unknown option: $current"
            ;;
        esac
        shift
    done
    if [ -z "$slotCount" ]; then
        slotCount="4"
    fi
    if [ "$slotCount" -gt "0" ]; then
        local offset=$(("$slotCount" * "$slotOffsetFactor"))
        local count="-1"
        local found=""
        for option in "${csOptions[@]}"; do
            count=$((count+1))
            if [ "$option" = "-o" ]; then
                count=$((count+1))
                csOptions[$count]="$offset"
                found="1"
                break
            fi
        done
        if [ -z "$found" ]; then
            csOptions+=( "-o" "$offset" )
        fi
    fi
}

function main()
{
    local mode="${1:-}"
    if [ -z "$mode" ]; then
        showChecksum
        showHelp
        exit 1
    fi
    shift

    case "$mode" in
        olr)
            cmsMountReadOnly="1"
        ;&
        ol)
            csmLive="1"
            csmCleanScreen="1"
        ;&
        open|o)
            openContainer "-" "$@"
            if [ "$csmLive" = "1" ]; then
                trap cleanUp 0 SIGHUP SIGINT SIGQUIT SIGTERM SIGABRT SIGQUIT
                tput setaf 1
                read -p "Press Enter twice or Ctrl+C to close the container ..."
                logError
                read -p "Press Enter once more or Ctrl+C to close the container ..."
                tput sgr 0
                logError
                cleanUp
            fi
        ;;
        #openNamed|openName|on)
        #    openContainer "$@"  
        #;;
        close|c)
            closeContainer "$1"
        ;;
        mount|m)
            mountContainer "$1"
        ;;
        umount|u)
            umountContainer "$1"
        ;;
        create|n|new)
            createContainer "$@"            
        ;;
        x)
            set +e
            "${csmkeyTool}" x
            set -e
        ;&
        closeAll|ca)
            closeAll
            cleanMntDir
        ;;
        list|l)
            processOptions "$@"
            closeAll "1"
        ;;
        resize|r)
            resizeContainer "$1"
        ;;
        increase|inc|i)
            increaseContainer "$@"
        ;;
        touch|t)
            touchDiskFile "$@"
        ;;
        synctime|st)
            systemctl restart systemd-timesyncd
            sleep 1
            date
        ;;
        chp)
            changePassword "$@"
        ;;
        k)
            "${csmkeyTool}" "$@"
        ;;
        cp)
            copyDir "$@"
        ;;
        rsync)
            rsyncDir "$@"
        ;;
        dcq)
            dcShowInfo="0"
        ;&
        dc)
            dcCleanFreeDiskSpace "$@"
        ;;
        d|disk|disks)
            echo -e "# Disks:\n"
            df -h -T -x tmpfs -x devtmpfs -x squashfs
            echo -e "\n# Devices:\n"
            lsblk | grep -vE 'loop|ram'
        ;;
        e|embed)
            embedSecret "$@"
        ;;
        ex|extract)
            extractSecret "$@"
        ;;
        *)
            showChecksum
            showHelp
        ;;
    esac
}

main "$@"
