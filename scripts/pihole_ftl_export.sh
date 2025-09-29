#!/bin/bash
DB="/etc/pihole/pihole-FTL.db"
OUT="/var/log/pihole/ftl_export.log"
LASTFILE="/var/log/pihole/ftl_export.last"

# якщо файл не існує - почати з 0
if [ ! -f "$LASTFILE" ]; then
  echo 0 > "$LASTFILE"
fi

LAST_TS=$(cat "$LASTFILE")

# Вибираємо тільки нові записи
NEW_ROWS=$(sudo sqlite3 -csv $DB "
SELECT
    q.timestamp,
    q.type,
    q.status,
    q.client,
    q.domain,
    q.forward,
    q.reply_type,
    q.additional_info
FROM queries q
WHERE q.timestamp > $LAST_TS
ORDER BY q.timestamp ASC;
")

# Якщо є нові рядки – додаємо в лог і оновлюємо last timestamp
if [ ! -z "$NEW_ROWS" ]; then
  echo "$NEW_ROWS" >> "$OUT"
  # Витягнемо максимальний timestamp із нових рядків
  MAX_TS=$(echo "$NEW_ROWS" | tail -n1 | cut -d',' -f1)
  echo "$MAX_TS" > "$LASTFILE"
fi

