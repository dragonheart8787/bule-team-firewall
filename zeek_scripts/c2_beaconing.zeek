
@load base/frameworks/notice
@load base/frameworks/notice/actions/email

module C2Beaconing;

export {
    redef enum Notice::Type += {
        C2_Beaconing_Detected
    };
}

global beacon_connections: table[addr, addr, port] of count &default=0;
global beacon_timestamps: table[addr, addr, port] of time &default=0;

event connection_established(c: connection) {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local port = c$id$resp_p;
    
    # 檢測定期連接模式
    if (src in beacon_connections) {
        local current_time = network_time();
        local last_time = beacon_timestamps[src, dst, port];
        
        if (current_time - last_time > 30 sec && current_time - last_time < 300 sec) {
            beacon_connections[src, dst, port] += 1;
            
            if (beacon_connections[src, dst, port] > 5) {
                NOTICE([$note=C2_Beaconing_Detected,
                       $msg=fmt("Potential C2 beaconing detected: %s -> %s:%d", src, dst, port),
                       $conn=c]);
            }
        }
    } else {
        beacon_connections[src, dst, port] = 1;
    }
    
    beacon_timestamps[src, dst, port] = network_time();
}
