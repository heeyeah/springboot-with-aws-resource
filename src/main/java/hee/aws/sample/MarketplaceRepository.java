package hee.aws.sample;

import org.springframework.data.elasticsearch.repository.ElasticsearchRepository;
import org.springframework.stereotype.Repository;

import java.math.BigDecimal;
import java.util.List;

@Repository
public interface MarketplaceRepository extends ElasticsearchRepository<Product, String> {
    List<Product> findByNameLikeAndPriceGreaterThan(String name, BigDecimal price);
}