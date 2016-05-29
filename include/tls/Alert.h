#ifndef ALERT_H_INCLUDED
#define ALERT_H_INCLUDED

#include "tls/RecordProtocol.h"

namespace CKTLS {

class Alert : public RecordProtocol {

    public:
        Alert();
        Alert(AlertDescription d, AlertLevel l = fatal);
        ~Alert();
        Alert(const Alert& other);
        Alert& operator=(const Alert& other);

    public:
        AlertDescription getDescription() const;
        AlertLevel getLevel() const;
        void setDescription(AlertDescription d);
        void setLevel(AlertLevel l);

    protected:
        void decode();
        void encode();

    private:
        AlertDescription desc;
        AlertLevel level;

};

}

#endif  // ALERT_H_INCLUDED
