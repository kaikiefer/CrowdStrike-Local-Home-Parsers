// Review these records to extend mappings with actual DSM/package samples.
#Vendor=synology #event.module=dsm
Parser.status != parsed OR Parser.timestamp_source=collector
| table([@timestamp, observer.name, #event.dataset, Parser.status, Parser.timestamp_source, log.level, message, @rawstring], limit=1000)
