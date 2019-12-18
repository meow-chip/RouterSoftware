enum TCPStatus {
    CLOSED,
    LISTEN,
    SYNRCVD,
    SYNSENT,
    CONNESBL,
    FINWAIT1,
    FINWAIT2,
    CLOSING,
    TIMEWAIT,
    CLOSEWAIT,
    LASTACK,
} status;

enum TCPFlag {
    SYN = 1,
    ACK = 2,
    FIN = 4,
    RST = 8,
};

extern void send(unsigned int flag);

void receive(unsigned int flag) {
    switch (status) {
    case CLOSED:
        // active open
        // passive open
        break;
    case LISTEN:
        if (flag == SYN) {
            send(SYN | ACK);
            status = SYNRCVD;
        }
        break;
    case SYNRCVD:
        if (flag == ACK) {
            status = CONNESBL;
        }
        break;
    case SYNSENT:
        if (flag == SYN) {
            send(ACK);
            status = SYNRCVD;
        }
        if (flag == (SYN | ACK)) {
            send(ACK);
            status = CONNESBL;
        }
        break;
    case CONNESBL:
        if (flag == FIN) {
            send(ACK);
            status = CLOSEWAIT;
        }
        // active close
        break;
    case FINWAIT1:
        if (flag == ACK) {
            status = FINWAIT2;
        } else if (flag == FIN) {
            send(ACK);
            status = CLOSING;
        } else if (flag == (FIN | ACK)) {
            send(ACK);
            status = TIMEWAIT;
        }
        break;
    case FINWAIT2:
        if (flag == FIN) {
            send(ACK);
            status = TIMEWAIT;
        }
        break;
    case CLOSING:
        if (flag == ACK) {
            status = TIMEWAIT;
        }
        break;
    case TIMEWAIT:
        // wait for timeout
        break;
    case CLOSEWAIT:
        // wait for close then
        {
            send(FIN);
            status = LASTACK;
        }
        break;
    case LASTACK:
        if (flag == ACK) {
            status = CLOSED;
            send(ACK);
        }
        break;
    }
}