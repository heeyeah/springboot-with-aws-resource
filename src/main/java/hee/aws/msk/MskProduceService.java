package hee.aws.msk;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class MskProduceService {

    private final static Logger log = LoggerFactory.getLogger(MskProduceService.class);
    private final KafkaTemplate<String, String> kafkaTemplate;

    public void sendMessage(String topic, String message) {
        log.info(" {} / {}", topic, message);
        kafkaTemplate.send(topic, message);
    }
}
