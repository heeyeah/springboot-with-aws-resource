package hee.aws.sample;


import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigDecimal;
import java.util.List;

@RestController
@RequestMapping("/marketplace")
public class MarketplaceRestController {
    private final MarketplaceRepository repository;

    public MarketplaceRestController(MarketplaceRepository repository) {
        this.repository = repository;
    }

    @GetMapping(value = "/search", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<Product> search(
            @RequestParam(value = "name", required = false, defaultValue = "") String name,
            @RequestParam(value = "price", required = false, defaultValue = "0.0") BigDecimal price) {
        return repository.findByNameLikeAndPriceGreaterThan(name, price);
    }
}