
@load base/frameworks/notice

module DNSTunneling;

export {
    redef enum Notice::Type += {
        DNS_Tunneling_Detected
    };
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    # 檢測可疑的 DNS 查詢
    local suspicious_patterns = /^[a-zA-Z0-9]{50,}$/;  # 長隨機字串
    local subdomain_count = |split_string(query, /\./)|;
    
    if (suspicious_patterns in query || subdomain_count > 5) {
        NOTICE([$note=DNS_Tunneling_Detected,
               $msg=fmt("Potential DNS tunneling detected: %s", query),
               $conn=c]);
    }
}
