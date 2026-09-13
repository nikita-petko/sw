$bytes = [System.IO.File]::ReadAllBytes("handshake_first_2_data_frames.pcapng")
$offset = 0
$pktCount = 0

while ($offset -lt $bytes.Length) {
    $blockType = [BitConverter]::ToUInt32($bytes, $offset)
    $blockLen = [BitConverter]::ToUInt32($bytes, $offset + 4)
    if ($blockLen -lt 12 -or ($offset + $blockLen) -gt $bytes.Length) { break }
    
    if ($blockType -eq 6) {
        $pktCount++
        $capLen = [BitConverter]::ToUInt32($bytes, $offset + 20)
        $pktData = $bytes[($offset + 28)..($offset + 28 + $capLen - 1)]
        
        $ipHeaderLen = ($pktData[14] -band 0x0F) * 4
        $tcpStart = 14 + $ipHeaderLen
        $tcpHeaderLen = (($pktData[$tcpStart + 12] -shr 4) -band 0x0F) * 4
        
        $srcPort = ($pktData[$tcpStart] * 256) + $pktData[$tcpStart + 1]
        $dstPort = ($pktData[$tcpStart + 2] * 256) + $pktData[$tcpStart + 3]
        
        # Relative seq/ack
        $seq = [uint32](($pktData[$tcpStart+4] * 16777216) + ($pktData[$tcpStart+5] * 65536) + ($pktData[$tcpStart+6] * 256) + $pktData[$tcpStart+7])
        $ack = [uint32](($pktData[$tcpStart+8] * 16777216) + ($pktData[$tcpStart+9] * 65536) + ($pktData[$tcpStart+10] * 256) + $pktData[$tcpStart+11])
        
        $payloadStart = $tcpStart + $tcpHeaderLen
        $payloadLen = $capLen - $payloadStart
        
        if ($pktCount -le 10) {
            $pData = if ($payloadLen -gt 0) { [BitConverter]::ToString($pktData, $payloadStart, [Math]::Min($payloadLen, 16)) } else { "NONE" }
            Write-Host "Pkt $pktCount | Port $srcPort -> $dstPort | RawSeq=$seq RawAck=$ack | PayLen=$payloadLen | PayHex=$pData"
        }
    }
    $offset += $blockLen
}
