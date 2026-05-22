#!/bin/sh
set -e

TARGET="${1:-all}"
MODEL_FILE="${2:-tm.py}"
MODEL=$(basename "${MODEL_FILE}" .py)
WORK_DIR=/work
OUTPUT_DIR="${WORK_DIR}/${MODEL}"

if [ ! -f "${WORK_DIR}/${MODEL_FILE}" ]; then
    echo "Error: ${MODEL_FILE} not found in mounted directory"
    echo "Usage: docker run --rm -v \$(pwd):/work pytm [dfd|seq|report|all] [model.py]"
    exit 1
fi

mkdir -p "${OUTPUT_DIR}"

run_dfd() {
    echo "Generating DFD..."
    python "${WORK_DIR}/${MODEL}.py" --dfd | dot -Tpng -o "${OUTPUT_DIR}/dfd.png"
}

run_seq() {
    echo "Generating sequence diagram..."
    python "${WORK_DIR}/${MODEL}.py" --seq \
        | java -Djava.awt.headless=true -jar "${PLANTUML_PATH}" -tpng -pipe \
        > "${OUTPUT_DIR}/seq.png"
}

run_report() {
    echo "Generating report..."
    python "${WORK_DIR}/${MODEL}.py" --report /app/docs/basic_template.md \
        | pandoc -f markdown-tex_math_dollars -t html \
        > "${OUTPUT_DIR}/report.html"
}

case "${TARGET}" in
    dfd)    run_dfd ;;
    seq)    run_seq ;;
    report) run_report ;;
    all)
        run_dfd
        run_seq
        run_report
        ;;
    *)
        echo "Unknown target: ${TARGET}"
        echo "Usage: docker run --rm -v \$(pwd):/work pytm [dfd|seq|report|all] [model.py]"
        exit 1
        ;;
esac

echo "Output written to ${MODEL}/"
