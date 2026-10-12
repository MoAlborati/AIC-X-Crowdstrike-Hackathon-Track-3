// In-process hook for the T2 proxy (PR #14): `createProxy(config, { sink })` accepts any object with
// `write(record)` and `flush()`. PipelineSink keeps the proxy's own JSONL sink and also feeds every
// record to the pipeline. The dashboard sees each alert as soon as the exchange is captured.
//
// Failure semantics (fail-closed, same as T2's own sink): if the pipeline throws (a bound exceeded,
// an invalid verdict, a disk error), write() rejects. The proxy then answers 503 and logs a
// `capture_write_failed` ALERT. The exchange line is already in the proxy JSONL, because the inner
// sink is written first.

//
// `takeExtraVerdicts(requestId)` (optional): extra verdicts to merge into an exchange record before both
// the proxy JSONL and the pipeline see it. Not used for T3 since #41: the proxy records T3's alert-only
// (`flagged: false, alert: true`) verdicts itself, and merging them again would duplicate every alert.
export class PipelineSink {
  constructor(inner, pipeline, { takeExtraVerdicts = null } = {}) {
    this.inner = inner;
    this.pipeline = pipeline;
    this.takeExtraVerdicts = takeExtraVerdicts;
  }

  async write(rec) {
    let record = rec;
    if (this.takeExtraVerdicts && record?.type === 'exchange') {
      const extra = this.takeExtraVerdicts(record.request_id);
      if (extra.length) record = { ...record, verdicts: [...(record.verdicts ?? []), ...extra] };
    }
    await this.inner.write(record);
    await this.pipeline.ingest(record);
    await this.pipeline.flush();
  }

  async flush() {
    await this.inner.flush();
    await this.pipeline.finish();
  }
}
