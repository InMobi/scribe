#!/usr/local/bin/thrift --gen cpp:pure_enums --gen java

namespace java com.inmobi.audit.thrift
namespace cpp  audit.thrift

struct AuditMetrics {
        1: i64 count,
        2: i64 size
}

struct AuditMessage
{
  1: i64 timestamp,
  2: string topic,
  3: string tier,
  4: string hostname,
  5: i32 windowSize,
  6: map<i64,i64> received,
  7: map<i64,i64> sent,
  8: list<string> filenames,
  9: map<string, string> tags,
  10: map<i64, AuditMetrics> receivedMetrics,
  11: map<i64, AuditMetrics> sentMetrics
}