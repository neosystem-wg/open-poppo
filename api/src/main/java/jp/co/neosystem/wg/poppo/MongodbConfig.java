package jp.co.neosystem.wg.poppo;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.config.AbstractMongoClientConfiguration;
import org.springframework.data.mongodb.gridfs.GridFsTemplate;

@Configuration
public class MongodbConfig extends AbstractMongoClientConfiguration {

	@Value("${spring.data.mongodb.uri}")
	private String dbUri;

	@Value("${spring.data.mongodb.database}")
	private String databasename;

	@Override
	protected String getDatabaseName() {
		return databasename;
	}

	@Override
	public MongoClient mongoClient() {
		return MongoClients.create(dbUri);
	}

	@Bean
	public GridFsTemplate gridFsTemplate() throws Exception {
		return new GridFsTemplate(mongoDbFactory(), mappingMongoConverter(mongoDbFactory(), customConversions(), mongoMappingContext(customConversions())));
	}
}
