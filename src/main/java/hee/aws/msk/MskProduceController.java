package hee.aws.msk;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class MskProduceController {

    private final static Logger log = LoggerFactory.getLogger(MskProduceController.class);
    private final MskProduceService mskProduceService;

    @GetMapping("/msk/{topic}")
    public ResponseEntity<?> sendMessageWithTopic(@PathVariable String topic, @RequestParam String message) {

        log.info("Controller => {}, {}", topic, message);

        mskProduceService.sendMessage(topic, message);

        return ResponseEntity.ok().build();
    }
}
