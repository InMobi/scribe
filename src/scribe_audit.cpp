//  Copyright (c) 2007-2009 Facebook
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//
// See accompanying file LICENSE or visit the Scribe site at:
// http://developers.facebook.com/scribe/
//
// @author Satish Mittal

#include "common.h"
#include "scribe_server.h"

using namespace std;
using namespace boost;
using namespace scribe::thrift;
using namespace apache::thrift::concurrency;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;
using namespace audit::thrift;

// magic bytes used to validate message header
unsigned char const magicBytes[] = {0xAB, 0xCD, 0xEF};
// assuming that logEntry message is of the format:
// [<version><magic bytes><timestamp><message size>]<message>
// number of bytes taken by header = 1 + 3 + 8 + 4 = 16
const int headerLength = 16;
// minimum cut-off value of timestamp (01-Jan-2013)
const unsigned long long minTimestamp = 1356998400000LL;
// constant string for file store tier name
static const string fileStoreTier = "hdfs";

/* 
** The Audit Manager class encapsulates the message audit functionality 
** within scribe. 
**
** An instance of this class is created by scribe at initialization time
** if it finds a store with category "_audit" configured in the scribe
** configuration file. This configuration can be used to turn on/off the
** audit functionality within scribe. The scribe server holds a reference
** to this instance and also passes it to all stores, including the ones
** created at run-time.
**
** The Audit Manager class provides methods that can be used by various
** threads to perform actions related to audit functionality:
**
** A) The methods auditMessage() and auditMessages() are called by Thrift
** server threads and file/network store queue threads to audit the event 
** that they have received/sent messages for a given topic. Note that these
** methods update the audit counters within in-memory maps owned by this
** class in a synchronized manner. The auditMessages() method can also audit
** on behalf of file store tier when messages are sent by file store threads. 
**
** B) The method performAuditTask() is called only by the store queue thread
** that scribe creates for the "_audit" category. This method periodically
** iterates through in-memory audit maps, converts each entry into an
** Audit instance and serializes the latter into a LogEntry instance. These
** audit objects are written into the file location configured for "_audit".
*/
AuditManager::AuditManager(const shared_ptr<StoreQueue> pAuditStore) {
  auditStore = pAuditStore;
  auditRWMutex = scribe::concurrency::createReadWriteMutex();
  // get hostname
  char hostname[255];
  int error = gethostname(hostname, sizeof(hostname));
  if (error) {
    LOG_OPER("[Audit] WARNING: gethostname returned error: %d ", error);
  }
  string hostString(hostname);
  if (hostString.empty()) {
    LOG_OPER("[Audit] WARNING: could not get host name");
  } else {
    hostName = hostString;
  }
  // get tier and windowSize from audit config
  pStoreConf pConf = auditStore->getStoreConfig();
  if (pConf != NULL) {
    pConf->getString("tier", tier);
    pConf->getInt("window_size", windowSize);
  } else {
    // set default values
    tier = "scribe";
    windowSize = 60;
  }
  //add audit version entry to tags map
  tags.insert(std::pair<std::string, std::string>("auditVersion", currentAuditVersion));
}

AuditManager::~AuditManager() {
  shared_ptr<audit_msg_t> audit_msg;
  audit_map_t::iterator audit_iter;
  // destroy mutex instance for each audit message in the map
  for (audit_iter = auditMap.begin(); audit_iter != auditMap.end(); audit_iter++) {
    audit_msg = audit_iter->second;
    pthread_mutex_destroy(&(audit_msg->mutex));
  } 
}

// This method audits the event that a message was received/sent for a given topic.
// E.g. Thrift threads call this method when a message is received by scribe.
void AuditManager::auditMessage(const LogEntry& entry, bool received) {
  // this store queue must be configured for audit topic 
  if (!auditStore->isAuditStore()) {
    return;
  }

  // get the timestamp of message
  unsigned long long tsKey = 0;
  int msgSize = 0;
  try {
    if (validateMessage(entry)) {
      tsKey = getTimestamp(entry);
      msgSize = getMsgSize(entry);
    LOG_OPER("[_audit] validate audit message, tsKey [%llu] and msgSize [%d]", tsKey, msgSize);
    } else {
      LOG_OPER("[Audit] msg not valid");
    }
    // if tsKey is 0 or msgSize is 0, then message doesn't have a valid header; hence skip it
    if (tsKey == 0 || msgSize == 0)
      return;
  } catch (const std::exception& e) {
    LOG_OPER("[Audit] Failed to validate message. Error <%s>", e.what());
    return;
  } catch (...) { 
    LOG_OPER("[Audit] Failed to validate message. Unexpected error.");
    return;
  }

  // acquire read lock on auditRWMutex. This allows multiple threads to audit
  // their messages concurrently when audit store queue thread is not performing 
  // periodic task to generate audit messages from maps.
  auditRWMutex->acquireRead();
  
  try {
    // get the audit message entry in audit map for the given category 
    shared_ptr<audit_msg_t> audit_msg = getAuditMsg(entry.category);

    // update audit message counter for the given message
    updateAuditMessageCounter(audit_msg, tsKey, received, msgSize);

    // finally, release the audit RW mutex
    auditRWMutex->release();
  } catch (const std::exception& e) {
    LOG_OPER("[Audit] Failed to audit message. Error <%s>", e.what());
    // release audit RW mutex, else it could block other threads waiting on mutex
    auditRWMutex->release();
    return;
  } catch (...) { 
    LOG_OPER("[Audit] Failed to audit message. Unexpected error.");
    // release audit RW mutex, else it could block other threads waiting on mutex
    auditRWMutex->release();
    return;
  }
}

// This method audits the event that a batch of messages were received/sent for
// a given topic. E.g. Network/file store threads call this method after they
// successfully write a batch of messages to their stores. Additionally, this 
// method also audits on behalf of file store tier when messages are sent by 
// primary file store threads.
void AuditManager::auditMessages(shared_ptr<logentry_vector_t>& messages, 
     unsigned long offset, unsigned long count, const string& category, bool received,
     bool auditFileStore, const string& filename) {
  // this store queue must be configured for audit topic 
  if (!auditStore->isAuditStore()) {
    return;
  }
  LOG_OPER("[Audit] audit arry of messages");
  // acquire read lock on auditRWMutex. This allows multiple threads to audit their
  // messages concurrently when audit store queue thread is not performing periodic
  // task to generate audit messages from maps.
  auditRWMutex->acquireRead();

  try {
    // get the audit message entry in audit map for the given category 
    shared_ptr<audit_msg_t> audit_msg = getAuditMsg(category);

    // if file store audit is enabled, get file audit message entry for given filename
    shared_ptr<file_audit_msg_t> file_audit_msg;
    if (auditFileStore) {
      file_audit_msg = getFileAuditMsg(filename, category);
    }

    for (unsigned long index = offset; index < offset + count; index++) {
      // get the timestamp of message
      unsigned long long tsKey = 0;
      int msgSize = 0;
      if (validateMessage(*(messages->at(index)))) {
        tsKey = getTimestamp(*(messages->at(index)));
        msgSize = getMsgSize(*(messages->at(index)));
      }
      // if tsKey is 0 or msgSize is 0, then probably message doesn't have a valid header; hence skip it
      if (tsKey == 0 || msgSize == 0)
        continue;

      // update audit message counter for the given message
      updateAuditMessageCounter(audit_msg, tsKey, received, msgSize);

      // if file store audit is enabled and messages are sent to file store, update 
      // file audit counters for given message
      if (auditFileStore && file_audit_msg != NULL && file_audit_msg.get() != NULL
          && received == false) {
        updateFileAuditMessageCounter(file_audit_msg, tsKey, msgSize);
      }
    }

    // finally, release the audit RW mutex
    auditRWMutex->release();
  } catch (const std::exception& e) {
    LOG_OPER("[Audit] Failed to audit message. Error <%s>", e.what());
    // release audit RW mutex, else it could block other threads waiting on mutex
    auditRWMutex->release();
    return;
  } catch (...) { 
    LOG_OPER("[Audit] Failed to audit message. Unexpected error.");
    // release audit RW mutex, else it could block other threads waiting on mutex
    auditRWMutex->release();
    return;
  }
}

// Get the audit message entry in audit map for the given category. If the entry
// is not found, this method adds an entry and returns it.
shared_ptr<audit_msg_t> AuditManager::getAuditMsg(const string& category) {
  shared_ptr<audit_msg_t> audit_msg;
  audit_map_t::iterator audit_iter;
  // search for the audit msg entry in audit map 
  if ((audit_iter = auditMap.find(category)) != auditMap.end()) {
    audit_msg = audit_iter->second;
  }

  if (audit_msg == NULL) {
    // acquire write lock to add a new audit message for this category
    auditRWMutex->release();
    auditRWMutex->acquireWrite();

    if ((audit_iter = auditMap.find(category)) != auditMap.end()) {
      audit_msg = audit_iter->second;
    } else {
      // create a new audit message for this category
      audit_msg = shared_ptr<audit_msg_t>(new audit_msg_t);
      audit_msg->topic = category;
      // initialize the mutex associated with this audit message
      pthread_mutex_init(&(audit_msg->mutex), NULL);
      // initialize the received/sent counters for this category
      audit_msg->receivedCount = 0;
      audit_msg->sentCount = 0;
      // add audit msg to audit map
      auditMap[category] = audit_msg;
    }
  }

  return audit_msg;
}

// Get the file audit message entry in file audit map for the given filename/category.
// If the entry is not found, this method adds an entry and returns it.
shared_ptr<file_audit_msg_t> AuditManager::getFileAuditMsg(const string& filename,
      const string& category) {
  shared_ptr<file_audit_msg_t> file_audit_msg;
  file_audit_map_t::iterator file_audit_iter;
  // search for the file audit msg entry in file audit map 
  if ((file_audit_iter = fileAuditMap.find(filename)) != fileAuditMap.end()) {
    file_audit_msg = file_audit_iter->second;
  }

  if (file_audit_msg == NULL) {
    // acquire write lock to add a new file audit message for this filename
    auditRWMutex->release();
    auditRWMutex->acquireWrite();

    if ((file_audit_iter = fileAuditMap.find(filename)) != fileAuditMap.end()) {
      file_audit_msg = file_audit_iter->second;
    } else {
      // create a new file audit message for this file name
      file_audit_msg = shared_ptr<file_audit_msg_t>(new file_audit_msg_t);
      file_audit_msg->topic = category;
      file_audit_msg->filename = filename;
      // initialize the file closed flag to false
      file_audit_msg->fileClosed = false;
      // initialize the received counter for this entry
      file_audit_msg->receivedCount = 0;
      // add file audit msg to audit map
      fileAuditMap[filename] = file_audit_msg;
    }
  }

  return file_audit_msg;
}

// This method updates the sent/received counter for the given message entry and its 
// corresponding timestamp key in the sent/received map.
void AuditManager::updateAuditMessageCounter(shared_ptr<audit_msg_t>& audit_msg,
       unsigned long long timestampKey, bool received, int msgSize) {
  // acquire category level mutex to synchronize access to map and insert/increment 
  // the received/sent counters.
  pthread_mutex_lock(&(audit_msg->mutex));
  if (received) {
    unsigned long long counter = audit_msg->received[timestampKey];
    audit_msg->received[timestampKey] = ++counter;
    ++(audit_msg->receivedCount);
    //for audit version 2
    unsigned long long prevCount = audit_msg->receivedMetrics[timestampKey].count;
    audit_msg->receivedMetrics[timestampKey].count = ++prevCount;
    unsigned long long prevSize = audit_msg->receivedMetrics[timestampKey].size;
    audit_msg->receivedMetrics[timestampKey].size = prevSize + msgSize;
    LOG_OPER("[audit] XXXX topic: [%s] prevCount: [%llu], prevsize: [%llu]", audit_msg->topic.c_str(), prevCount, prevSize);
    LOG_OPER("[audit] XXXX topic: [%s] currCount: [%lu], currsize: [%lu]", audit_msg->topic.c_str(), audit_msg->receivedMetrics[timestampKey].count, audit_msg->receivedMetrics[timestampKey].size);
  } else {
    unsigned long long counter = audit_msg->sent[timestampKey];
    audit_msg->sent[timestampKey] = ++counter;
    ++(audit_msg->sentCount);
    //for audit version 2
    unsigned long long prevCount = audit_msg->sentMetrics[timestampKey].count;
    audit_msg->sentMetrics[timestampKey].count = ++prevCount;
    unsigned long long prevSize = audit_msg->sentMetrics[timestampKey].size;
    audit_msg->sentMetrics[timestampKey].size = prevSize + msgSize;
    LOG_OPER("[audit] XXXX topic: [%s] prevCount: [%llu], prevsize: [%llu]", audit_msg->topic.c_str(), prevCount, prevSize);
    LOG_OPER("[audit] XXXX topic: [%s] currCount: [%lu], currsize: [%lu]", audit_msg->topic.c_str(), audit_msg->sentMetrics[timestampKey].count, audit_msg->sentMetrics[timestampKey].size);
  }
  pthread_mutex_unlock(&(audit_msg->mutex));
}

// This method updates the received counter for the given message entry and its 
// corresponding timestamp key in the received map. This method will be called
// only when messages are sent to a file store and auditFileStore flag is enabled.
void AuditManager::updateFileAuditMessageCounter(shared_ptr<file_audit_msg_t>& file_audit_msg,
       unsigned long long timestampKey, int msgSize) {
  unsigned long long counter = file_audit_msg->received[timestampKey];
  file_audit_msg->received[timestampKey] = ++counter;
  //for audit version 2
  unsigned long long prevCount = file_audit_msg->receivedMetrics[timestampKey].count;
  file_audit_msg->receivedMetrics[timestampKey].count = ++prevCount;
  unsigned long long prevSize = file_audit_msg->receivedMetrics[timestampKey].size;
  file_audit_msg->receivedMetrics[timestampKey].size = prevSize + msgSize;
  ++(file_audit_msg->receivedCount);
}

// This method audits the event that the given file is closed. This would allow audit 
// store thread to generate audit message for this file. 
void AuditManager::auditFileClosed(const std::string& filename) {
  // acquire read lock
  RWGuard rwMonitor(*auditRWMutex);

  // get the file audit message entry for given filename 
  shared_ptr<file_audit_msg_t> file_audit_msg;
  file_audit_map_t::iterator file_audit_iter;
  if ((file_audit_iter = fileAuditMap.find(filename)) != fileAuditMap.end()) {
    file_audit_msg = file_audit_iter->second;
  }

  // file audit entry should be present in map if messages were writen to this file.
  // Note that in case of empty files there won't be any entry in the file audit map.
  if (file_audit_msg == NULL) {
    return;
  }

  // set the fileClosed flag to true
  file_audit_msg->fileClosed = true;
}

// This method checks whether the given message has a valid header. If a valid header is
// found, it returns true, else returns false
bool AuditManager::validateMessage(const LogEntry& entry) {
  // assuming that logEntry message is of the format:
  // <version><magic bytes><timestamp><message size><message>
  
  // first check that total message length should be at least 16
  if ((int)entry.message.length() < headerLength) {
    LOG_OPER("[Audit] msg length is less than header length");
    return false;
  }

  const char* data = entry.message.data();

  // first validate the version byte
  int version = (int)(data[0]);
  if (version != 1 && version != 2) {
    LOG_OPER("[Audit] version does not match: [%d]", version);
    return false;
  }

  // now validate magic bytes. Note that in C++ there is no byte datatype.
  // Hence we need to cast each char to unsigned char to get the unsigned 
  // value for comparison.
  if ((((unsigned char)data[1]) != magicBytes[0]) || 
      (((unsigned char)data[2]) != magicBytes[1]) ||
      (((unsigned char)data[3]) != magicBytes[2])) {
    LOG_OPER("Magic bytes don't match");
    return false;
  }

  // now get long timestamp value. This involves left shift each char to its 
  // appropriate position. Note that each intermediate long after left shift 
  // will have leading bits set to that of the leading bit of each char (0/1). 
  // Hence we need to clear them using mask [0xff]. The same strategy is used 
  // in Thrift deserialization and Java as well (see java.io.Bits.getLong()).
  unsigned long long timestamp =
    ((long)(data[4]  & 0xff) << 56) |
    ((long)(data[5]  & 0xff) << 48) |
    ((long)(data[6]  & 0xff) << 40) |
    ((long)(data[7]  & 0xff) << 32) |
    ((long)(data[8]  & 0xff) << 24) |
    ((long)(data[9]  & 0xff) << 16) |
    ((long)(data[10] & 0xff) <<  8) |
    ((long)(data[11] & 0xff));

  // validate that timestamp value must be greater than min cut-off
  if (timestamp < minTimestamp) {
    LOG_OPER("[Audit] timestamp is less than mintimestamp, [%llu]", timestamp);
    return false;
  }

  // now validate that message size must be same as the length of message payload
  int size =
    ((int)(data[12] & 0xff) << 24) |
    ((int)(data[13] & 0xff) << 16) |
    ((int)(data[14] & 0xff) <<  8) |
    ((int)(data[15] & 0xff));
  if ((int)entry.message.length() != size + headerLength) {
    LOG_OPER("[Audit] entry message length[%d] is not equal to size + headerLength[%d]",(int)entry.message.length(), size + headerLength);
    return false;
  }

  LOG_OPER("[_audit] valid message ");
  return true;
}

// This method checks whether the given message has a valid header. If a valid header is
// found, this method returns message size else returns 0.
int AuditManager::getMsgSize(const LogEntry& entry) {
    const char* data = entry.message.data();

    int size =
    ((int)(data[12] & 0xff) << 24) |
    ((int)(data[13] & 0xff) << 16) |
    ((int)(data[14] & 0xff) <<  8) |
    ((int)(data[15] & 0xff));
    LOG_OPER("[_audit] Returning msg size: [%d]", size);
    return size;
}

// This method checks whether the given message has a valid header. If a valid header is
// found, this method returns timestamp key else returns 0.
unsigned long long AuditManager::getTimestamp(const LogEntry& entry) {
    const char* data = entry.message.data();

    unsigned long long timestamp =
    ((long)(data[4]  & 0xff) << 56) |
    ((long)(data[5]  & 0xff) << 48) |
    ((long)(data[6]  & 0xff) << 40) |
    ((long)(data[7]  & 0xff) << 32) |
    ((long)(data[8]  & 0xff) << 24) |
    ((long)(data[9]  & 0xff) << 16) |
    ((long)(data[10] & 0xff) <<  8) |
    ((long)(data[11] & 0xff));

    LOG_OPER("[_audit] returning timestamp [%llu]", timestamp);
    // If a valid header is found, convert the timestamp to a key that can be used 
    // to update the counter in received/sent map. The key is calculated based on 
    // window size audit config. E.g. if window size is 60 seconds, then all messages 
    // whose generation timestamp lie within 12:00 and 12:59 would be counted in the
    // bucket with key as 12:00
    return timestamp - timestamp % (windowSize * 1000);
}

// This method is called by audit store thread periodically to generate audit messages
// for all categories/file stores and add them to message queue.
void AuditManager::performAuditTask() {
  // find the current time in millis. This time will be set in audit messages
  // generated for all topics/file stores.
  struct timeval tv;
  gettimeofday(&tv, NULL);
  long timeInMillis = (tv.tv_sec * 1000) + (tv.tv_usec / 1000);

  // acquire write lock on auditRWMutex using RWGuard 
  RWGuard rwMonitor(*auditRWMutex, true);

  // counter for number of audit messages generated
  int auditMsgCount = 0;

  // Iterate through audit map; create a LogEntry instance from each audit message 
  // entry per topic and add it to message queue
  try {
    shared_ptr<audit_msg_t> audit_msg;
    audit_map_t::iterator audit_iter;
    LOG_OPER("[audit] XXXX Performing audit task, auditMap size [%d]", auditMap.size());
    for (audit_iter = auditMap.begin(); audit_iter != auditMap.end(); audit_iter++) {
      audit_msg = audit_iter->second;
        if (audit_msg->receivedMetrics.size() == 0 && audit_msg->sentMetrics.size() == 0)
        {
          LOG_OPER("XXXX metrics maps are empty");
        }
      // skip auditing if received & sent maps are both empty
      if (audit_msg->received.size() == 0 && audit_msg->sent.size() == 0) {
        LOG_OPER("XXXX Empty maps in audit_msg, continuing");
        continue;
      }

      LOG_OPER("[Audit] XXXX category [%s], messages received [%llu], messages sent [%llu]",
        audit_msg->topic.c_str(), audit_msg->receivedCount, audit_msg->sentCount);

      // create a LogEntry instance from audit msg
      shared_ptr<LogEntry> entry = serializeAuditMsg(audit_msg, timeInMillis);

      // add the LogEntry instance to store queue
      auditStore->addMessage(entry);

      // increment the audit message generation count
      ++auditMsgCount;

      // now clear the contents of received/sent maps within audit message instance
      audit_msg->received.clear();
      audit_msg->sent.clear();
      audit_msg->receivedMetrics.clear();
      audit_msg->sentMetrics.clear();

      // finally clear the received/sent counters for this audit message instance
      audit_msg->receivedCount = 0;
      audit_msg->sentCount = 0;
    }
  } catch (const std::exception& e) {
    LOG_OPER("[Audit] Store thread failed to perform message audit task. Error <%s>", e.what());
  } catch (...) {
    LOG_OPER("[Audit] Store thread failed to perform message audit task. Unexpected error");
  }

  // Iterate through file audit map; create a LogEntry instance for each file audit
  // entry if the file is closed  and add it to message queue
  try {
    shared_ptr<file_audit_msg_t> file_audit_msg;
    file_audit_map_t::iterator file_audit_iter = fileAuditMap.begin();
   
    while (file_audit_iter != fileAuditMap.end()) {
      file_audit_msg = file_audit_iter->second;
      
      // skip the entry if file is not closed yet
      if (file_audit_msg->fileClosed == false) {
        ++file_audit_iter;
      } else {
        // skip auditing if received map is empty
        if (file_audit_msg->received.size() != 0) {
          LOG_OPER("[Audit] category [%s], file [%s], messages received [%llu]",
          file_audit_msg->topic.c_str(), file_audit_msg->filename.c_str(), 
          file_audit_msg->receivedCount);

          // create a LogEntry instance from audit msg
          shared_ptr<LogEntry> entry = serializeFileAuditMsg(file_audit_msg, timeInMillis);

          // add the LogEntry instance to store queue
          auditStore->addMessage(entry);

          // increment the audit message generation count
          ++auditMsgCount;
        }
        // delete the entry from file audit map
        fileAuditMap.erase(file_audit_iter++);
      }
    }
  } catch (const std::exception& e) {
    LOG_OPER("[Audit] Store thread failed to perform file audit task. Error <%s>", e.what());
  } catch (...) {
    LOG_OPER("[Audit] Store thread failed to perform file audit task. Unexpected error");
  }

  // increment the audit message generated counter
  g_Handler->incCounter(auditTopic, "generated", auditMsgCount);
}

// This method serializes the audit message entry and sets it as the message payload
// of a logEntry instance. This instance will be later added in the audit thread queue.
shared_ptr<LogEntry> AuditManager::serializeAuditMsg(shared_ptr<audit_msg_t>& audit_msg, 
    long timeInMillis) {
  LOG_OPER("XXXX serialize audit_msg");
  // create an instance of Thrift AuditMessage from the given audit_msg
  boost::shared_ptr<AuditMessage> Audit = boost::shared_ptr<AuditMessage>(new AuditMessage);
  
  Audit->timestamp = timeInMillis;
  Audit->topic = audit_msg->topic;
  Audit->hostname = hostName;
  Audit->tier = tier;
  Audit->windowSize = windowSize;
  Audit->received = audit_msg->received; 
  Audit->sent = audit_msg->sent;
  Audit->tags = tags;
  Audit->receivedMetrics = audit_msg->receivedMetrics;
  Audit->sentMetrics = audit_msg->sentMetrics;

  // Perform in-memory Thrift serialization of Audit message content
  shared_ptr<TMemoryBuffer> tmembuf(new TMemoryBuffer);
  shared_ptr<TBinaryProtocol> tprot(new TBinaryProtocol(tmembuf));
  Audit->write(tprot.get());

  // create a LogEntry instance using the serialized payload as string
  shared_ptr<LogEntry> entry(new LogEntry);
  entry->category = auditTopic;
  entry->message = tmembuf->getBufferAsString();
  LOG_OPER("XXXX size of treceived metrics map of serialized audit obj:[%d] and sent metrics:[%d]", Audit->receivedMetrics.size(), Audit->sentMetrics.size());
  LOG_OPER("XXXX entry message: %s", entry->message.c_str());
  LOG_OPER("XXXX serialized audit_msg, returning");
  return entry; 
}

// This method serializes the file audit message entry and sets it as the message payload
// of a logEntry instance. This instance will be later added in the audit thread queue.
shared_ptr<LogEntry> AuditManager::serializeFileAuditMsg(shared_ptr<file_audit_msg_t>& file_audit_msg,
    long timeInMillis) {
  // create an instance of Thrift AuditMessage from the given file_audit_msg
  boost::shared_ptr<AuditMessage> Audit = boost::shared_ptr<AuditMessage>(new AuditMessage);

  Audit->timestamp = timeInMillis;
  Audit->topic = file_audit_msg->topic;
  Audit->hostname = hostName;
  Audit->tier = fileStoreTier;
  Audit->windowSize = windowSize;
  Audit->received = file_audit_msg->received;
  Audit->filenames.push_back(file_audit_msg->filename); 
  Audit->tags = tags;
  Audit->receivedMetrics = file_audit_msg->receivedMetrics;

  // Perform in-memory Thrift serialization of Audit message content
  shared_ptr<TMemoryBuffer> tmembuf(new TMemoryBuffer);
  shared_ptr<TBinaryProtocol> tprot(new TBinaryProtocol(tmembuf));
  Audit->write(tprot.get());

  // create a LogEntry instance using the serialized payload as string
  shared_ptr<LogEntry> entry(new LogEntry);
  entry->category = auditTopic;
  entry->message = tmembuf->getBufferAsString();

  return entry;
}
