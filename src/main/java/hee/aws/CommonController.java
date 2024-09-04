package hee.aws;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class CommonController {

    private final static Logger log = LoggerFactory.getLogger(CommonController.class);

    private final JdbcTemplate jdbcTemplate;

    @GetMapping("/opensearch")
    public ResponseEntity<?> queryInOpenSearch(@RequestParam String message) {

        String query = "SELECT * FROM opensearch_dashboards_sample_data_flights LIMIT 1";
        String result = jdbcTemplate.queryForList(query).toString();
        log.info("result={}", result);
        return ResponseEntity.ok().build();
    }
}
