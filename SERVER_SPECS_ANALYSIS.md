# Server Specifications Analysis for AutoAR + PostgreSQL

## Your Server Specs
- **RAM**: 4 GB
- **CPU**: 2 cores
- **Storage**: 80 GB SSD
- **Bandwidth**: 4 TB
- **Cost**: $24/month

## Resource Requirements Breakdown

### 1. AutoAR Application
- **Base Memory**: ~200-500 MB (Go binary + runtime)
- **During Active Scans**: 500 MB - 2 GB (depends on tools)
  - Nuclei: Can use 200-500 MB with 25 concurrent templates
  - Httpx: ~100-300 MB with 100 threads
  - Subfinder: ~50-200 MB
  - Multiple concurrent scans: Memory multiplies
- **Peak Usage**: Up to 2-3 GB during intensive scans

### 2. PostgreSQL Database
- **Minimum**: 1-2 GB RAM
- **Recommended**: 2-4 GB for active use
- **With AutoAR Data**: 
  - Scan results storage
  - Subdomain/domain data
  - Can grow significantly over time
- **Typical Usage**: 1.5-2.5 GB

### 3. Docker & Dokploy Overhead
- **Docker Daemon**: ~200-500 MB
- **Dokploy**: ~100-300 MB
- **Container Overhead**: ~100-200 MB per container
- **Total**: ~500 MB - 1 GB

### 4. System/OS
- **Debian/Ubuntu Base**: ~300-500 MB
- **System Services**: ~200-400 MB
- **Total**: ~500 MB - 1 GB

## Total Memory Estimate

| Scenario | AutoAR | PostgreSQL | Docker/Dokploy | System | **Total** |
|----------|--------|------------|----------------|--------|-----------|
| **Idle** | 300 MB | 1.5 GB | 600 MB | 500 MB | **~2.9 GB** ✅ |
| **Light Usage** | 800 MB | 2 GB | 700 MB | 600 MB | **~4.1 GB** ⚠️ |
| **Active Scans** | 1.5 GB | 2.5 GB | 800 MB | 700 MB | **~5.5 GB** ❌ |
| **Heavy Scans** | 2.5 GB | 2.5 GB | 1 GB | 800 MB | **~6.8 GB** ❌ |

## Recommendation: ⚠️ **TIGHT BUT WORKABLE**

### ✅ **Will Work If:**
1. **Lower Thread Counts**: Reduce default threads from 100 to 25-50
2. **Limited Concurrent Scans**: Run 1-2 scans at a time max
3. **PostgreSQL Tuning**: 
   - Set `shared_buffers = 512MB` (instead of default 1GB+)
   - Set `max_connections = 50` (lower than default)
   - Enable swap space (2-4 GB)
4. **Resource Limits**: Set Docker memory limits
5. **Monitor Usage**: Watch for OOM (Out of Memory) issues

### ❌ **Won't Work Well If:**
- Running multiple concurrent large scans
- High thread counts (100+)
- Large database with many domains
- No swap space configured
- Heavy Nuclei scanning with many templates

## Recommended Configuration

### AutoAR Thread Limits (in docker-compose.yml or .env)
```yaml
environment:
  - NUCLEI_CONCURRENCY=15        # Lower from 25
  - FFUF_THREADS=25              # Lower from 50
  - SUBFINDER_THREADS=5          # Lower from 10
  - HTPPX_THREADS=50             # Lower from 100
```

### PostgreSQL Tuning (postgresql.conf)
```conf
shared_buffers = 512MB           # 25% of RAM
effective_cache_size = 1GB       # 50% of RAM
maintenance_work_mem = 128MB
max_connections = 50
work_mem = 10MB
```

### Docker Memory Limits
```yaml
services:
  autoar-discord:
    deploy:
      resources:
        limits:
          memory: 2G
        reservations:
          memory: 1G
  postgres:
    deploy:
      resources:
        limits:
          memory: 1.5G
        reservations:
          memory: 1G
```

## Better Alternatives

### Option 1: Upgrade to 8 GB RAM ($40-50/month)
- **Pros**: Comfortable headroom, can run multiple scans
- **Cons**: 2x cost
- **Recommendation**: ⭐ **Best for production**

### Option 2: Separate Database Server
- **AutoAR Server**: 4 GB (current)
- **PostgreSQL Server**: 2-4 GB (separate, $12-20/month)
- **Total**: ~$36-44/month
- **Pros**: Better isolation, can scale independently
- **Cons**: Network latency, more complex setup

### Option 3: Use SQLite Instead of PostgreSQL
- **Pros**: No separate database process, lower memory
- **Cons**: Limited for concurrent writes, no advanced features
- **Memory Saved**: ~1.5-2 GB
- **Recommendation**: ⭐ **Good for single-user/small scale**

## My Recommendation

### For Testing/Development: ✅ **4 GB is OK**
- Use SQLite instead of PostgreSQL
- Lower thread counts
- Monitor closely

### For Production: ⚠️ **Upgrade to 8 GB**
- Better performance
- Can handle concurrent scans
- More reliable
- Worth the extra $16-26/month

### Quick Win: Start with 4 GB + SQLite
1. Test with current 4 GB server
2. Use SQLite (no PostgreSQL)
3. Lower thread counts
4. Monitor memory usage
5. Upgrade if needed

## Monitoring Commands

```bash
# Check memory usage
free -h
docker stats

# Check PostgreSQL memory
ps aux | grep postgres

# Monitor AutoAR container
docker stats autoar-discord
```

## Conclusion

**4 GB RAM is workable but tight.** You'll need to:
- ✅ Lower thread counts
- ✅ Limit concurrent scans  
- ✅ Consider SQLite instead of PostgreSQL
- ✅ Monitor memory usage closely
- ⚠️ Be prepared to upgrade if you hit limits

**For production use, 8 GB is recommended** for comfortable operation.
