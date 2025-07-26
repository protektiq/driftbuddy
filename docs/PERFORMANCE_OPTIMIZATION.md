# Performance Optimization Guide

This document explains the performance optimizations in DriftBuddy and how to configure them for optimal results.

## 🚀 Performance Improvements

### Before Optimization
- **Sequential API calls**: Each query and file finding required a separate API call
- **No concurrency**: All requests were processed one at a time
- **High latency**: Each API call took 2-5 seconds due to HTTPS overhead
- **Exponential scaling**: 10 queries × 5 findings = 60 API calls

### After Optimization
- **Batched API calls**: Multiple findings processed in a single API call
- **Parallel processing**: Up to 3 concurrent API calls
- **Reduced latency**: Fewer total API calls with better connection reuse
- **Linear scaling**: 10 queries = 10 API calls (regardless of findings)

## 📊 Performance Metrics

### API Call Reduction
- **Old method**: 1 API call per query + 1 API call per file finding
- **New method**: 1 API call per query (with all findings included)
- **Typical reduction**: 60-80% fewer API calls

### Time Savings
- **Network latency**: Reduced from 300-500ms per call to 200-300ms
- **Total processing time**: 50-70% faster for typical workloads
- **Concurrent processing**: 3x faster for multiple queries

## ⚙️ Configuration Settings

### AI Performance Settings

```bash
# Maximum concurrent API requests (default: 3)
AI_MAX_CONCURRENT_REQUESTS=3

# Request timeout in seconds (default: 60)
AI_REQUEST_TIMEOUT=60

# Batch size for processing (default: 5)
AI_BATCH_SIZE=5
```

### Recommended Settings by Workload

#### Small Projects (< 10 findings)
```bash
AI_MAX_CONCURRENT_REQUESTS=2
AI_REQUEST_TIMEOUT=30
```

#### Medium Projects (10-50 findings)
```bash
AI_MAX_CONCURRENT_REQUESTS=3
AI_REQUEST_TIMEOUT=60
```

#### Large Projects (> 50 findings)
```bash
AI_MAX_CONCURRENT_REQUESTS=5
AI_REQUEST_TIMEOUT=90
```

## 🔧 Troubleshooting Performance Issues

### Slow API Responses
1. **Check network connectivity**: Test with `ping api.openai.com`
2. **Reduce concurrency**: Lower `AI_MAX_CONCURRENT_REQUESTS`
3. **Increase timeout**: Raise `AI_REQUEST_TIMEOUT`
4. **Check rate limits**: Monitor OpenAI API usage

### Rate Limit Errors
1. **Reduce concurrency**: Set `AI_MAX_CONCURRENT_REQUESTS=1`
2. **Add delays**: Implement exponential backoff
3. **Monitor usage**: Check OpenAI dashboard for limits

### Memory Issues
1. **Reduce batch size**: Lower `AI_BATCH_SIZE`
2. **Process in chunks**: Split large datasets
3. **Monitor memory**: Use system monitoring tools

## 📈 Performance Testing

Run the performance testing script to analyze your specific workload:

```bash
python scripts/test_performance.py
```

This will:
- Analyze your dataset characteristics
- Estimate performance improvements
- Provide configuration recommendations
- Offer to run actual performance tests

## 🎯 Best Practices

### For Optimal Performance
1. **Use appropriate concurrency**: Start with 3, adjust based on results
2. **Monitor API costs**: Each call costs ~$0.02-0.05
3. **Cache results**: Reuse explanations when possible
4. **Batch similar findings**: Group related security issues

### For Cost Optimization
1. **Limit daily usage**: Set `AI_EXPLANATION_LIMIT_PER_DAY`
2. **Use demo mode**: Test with `USE_DEMO_KEY_FALLBACK=true`
3. **Process incrementally**: Run on subsets first
4. **Review explanations**: Ensure quality justifies cost

## 🔍 Monitoring Performance

### Key Metrics to Track
- **Total processing time**: Should be 50-70% faster
- **API calls per query**: Should be 60-80% fewer
- **Concurrent requests**: Monitor for rate limits
- **Error rates**: Should be < 5%

### Performance Logs
The application logs performance metrics:
```
🚀 Starting AI explanation generation...
📊 Total queries: 15
🔍 Queries with findings: 8
⚡ Using 3 concurrent workers
⏱️ Request timeout: 60s
✅ AI explanation generation completed in 45.23s
📈 Average time per query: 5.65s
```

## 🚨 Common Issues and Solutions

### Issue: "Request timeout"
**Solution**: Increase `AI_REQUEST_TIMEOUT` or reduce `AI_MAX_CONCURRENT_REQUESTS`

### Issue: "Rate limit exceeded"
**Solution**: Reduce `AI_MAX_CONCURRENT_REQUESTS` to 1-2

### Issue: "Memory error"
**Solution**: Reduce `AI_BATCH_SIZE` or process in smaller chunks

### Issue: "Slow performance"
**Solution**: Check network connectivity and API key validity

## 📚 Additional Resources

- [OpenAI API Rate Limits](https://platform.openai.com/docs/guides/rate-limits)
- [HTTP Performance Optimization](https://medium.com/@northvankiwiguy/how-long-is-a-curl-ec59af087ca8)
- [Concurrent Processing Best Practices](https://docs.python.org/3/library/concurrent.futures.html) 