function filter(packet , protocol)
    if packet.protcool != protocol then 
        return false
    end 
    return true
end
