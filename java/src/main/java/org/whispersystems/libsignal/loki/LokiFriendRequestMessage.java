package org.whispersystems.libsignal.loki;

import org.whispersystems.libsignal.protocol.CiphertextMessage;

public class LokiFriendRequestMessage implements CiphertextMessage {

    private final byte[] paddedMessageBody;

    public LokiFriendRequestMessage(byte[] paddedMessageBody) {
        this.paddedMessageBody = paddedMessageBody;
    }

    @Override
    public byte[] serialize() {
        return paddedMessageBody;
    }

    @Override
    public int getType() {
        return CiphertextMessage.LOKI_FRIEND_REQUEST_TYPE;
    }
}
