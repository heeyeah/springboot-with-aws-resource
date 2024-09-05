package hee.aws.opensearch;

import hee.aws.opensearch.dto.QueryRequest;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class OpenSearchConnectController {

    private final static Logger log = LoggerFactory.getLogger(OpenSearchConnectController.class);
    private final JdbcTemplate jdbcTemplate;

    @PostMapping("/opensearch")
    public ResponseEntity<?> queryInOpenSearch(@RequestBody QueryRequest request) {

        log.info("query={}", request.getQuery());
        List<Map<String, Object>> result = List.of();
        try {
            result = jdbcTemplate.queryForList(request.getQuery());

            for(val data : result) {
                data.keySet().forEach(key -> {
                    log.info("{}", data.get(key).toString());
                });
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return ResponseEntity.ok(result);
    }
}
