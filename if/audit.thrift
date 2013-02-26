#!/usr/local/bin/thrift --gen cpp:pure_enums --gen php

namespace cpp audit.thrift
namespace java com.inmobi.audit.thrift

struct AuditMessage
{
  1:  i64 timestamp,
  2:  string topic,
  3:  string tier,
  4:  string hostname,
  5:  i32 windowSize,
  6:  map<i64, i64> received,
  7:  map<i64, i64> sent,
  8:  list<string> filenames,
  9:  map<string, string> tags
}
