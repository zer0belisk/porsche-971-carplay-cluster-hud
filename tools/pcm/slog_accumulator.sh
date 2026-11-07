#!/bin/sh
# Bounded, deduplicating sloginfo accumulator. Keeps only unique lines.
ACC=/tmp/slogacc.txt
NEW=/tmp/slognew.txt
PAT='RVC|nvcapture|disables window|stream closed|new stream available|Modes changed|SessionScreen|ScreenStream|NvssVideoImpl|run fault|TearDown|Tearing down|kConnectionErr|<ERROR>|UpdateState|Modes '
: > $ACC
while :; do
    sloginfo 2>/dev/null | grep -E "$PAT" | grep -v 'Late frame' > $NEW
    cat $ACC $NEW | sort -u > $ACC.tmp && mv $ACC.tmp $ACC
    SZ=`wc -c < $ACC`
    if [ "$SZ" -gt 3000000 ]; then
        tail -2000 $ACC > $ACC.tmp && mv $ACC.tmp $ACC
    fi
    sleep 10
done
