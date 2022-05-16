package com.trecapps.auth.repos;

import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.orm.jpa.EntityManagerFactoryBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import javax.persistence.EntityManagerFactory;
import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableTransactionManagement
@EnableJpaRepositories (
		entityManagerFactoryRef = "primaryEntityManagerFactory",
        transactionManagerRef = "primaryTransactionManager",
        basePackages = {"com.trecapps.auth.repos.primary"})
public class PrimaryDataSourceConfiguration
{
	@Primary
	@Bean(name = "primaryDataSourceProperties")
	@ConfigurationProperties("trecauth.datasource-primary")
	public DataSourceProperties primaryDataSourceProperties()
	{
        return new DataSourceProperties();
    }
	
	@Primary
	@Bean(name = "primaryDataSource")
	@ConfigurationProperties("trecauth.datasource-primary.configuration")
	public DataSource primaryDataSource(@Qualifier("primaryDataSourceProperties") DataSourceProperties primaryDataSourceProperties) {
		DataSource ds = primaryDataSourceProperties.initializeDataSourceBuilder().type(HikariDataSource.class).build();
		return ds;
	}
	
	@Primary
	@Bean(name = "primaryEntityManagerFactory")
	public LocalContainerEntityManagerFactoryBean  primaryEntityManagerFactory(
			EntityManagerFactoryBuilder  primaryEntityManagerFactoryBuilder,
			@Qualifier("primaryDataSource") DataSource primaryDataSource) {
		
		Map<String, String> primaryJpaProperties = new HashMap<>();
        primaryJpaProperties.put("hibernate.dialect", System.getenv("DB_DIALECT"));
        primaryJpaProperties.put("hibernate.hbm2ddl.auto", "update");
        primaryJpaProperties.put("hibernate.enable_lazy_load_no_trans", "true");

        LocalContainerEntityManagerFactoryBean ret = primaryEntityManagerFactoryBuilder
			.dataSource(primaryDataSource)
			.packages("com.trecapps.auth.models.primary")
			.persistenceUnit("primaryDataSource")
			.properties(primaryJpaProperties)
			.build();

        return ret;
	}
	
	@Primary
    @Bean(name = "primaryTransactionManager")
    public PlatformTransactionManager primaryTransactionManager(
            @Qualifier("primaryEntityManagerFactory") EntityManagerFactory primaryEntityManagerFactory) {

        return new JpaTransactionManager(primaryEntityManagerFactory);
    }
}