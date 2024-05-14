package com.trecapps.auth.web.repos;

import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.orm.jpa.EntityManagerFactoryBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import jakarta.persistence.EntityManagerFactory;
import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableTransactionManagement
@EnableJpaRepositories(
        entityManagerFactoryRef = "secondaryEntityManagerFactory",
        transactionManagerRef = "secondaryTransactionManager",
        basePackages = {"com.trecapps.auth.web.repos.secondary"})
@ConditionalOnProperty(prefix = "trecauth", name = "login", havingValue = "true")
public class SecondaryDataSourceConfiguration {
    @Bean(name = "secondaryDataSourceProperties")
    @ConfigurationProperties("trecauth.datasource-secondary")

    @ConditionalOnProperty(prefix = "trecauth", name = "login", havingValue = "true")
    public DataSourceProperties secondaryDataSourceProperties() {
        return new DataSourceProperties();
    }

    @Bean(name = "secondaryDataSource")
    @ConfigurationProperties("trecauth.datasource-secondary.configuration")
    @ConditionalOnProperty(prefix = "trecauth", name = "login", havingValue = "true")
    public DataSource secondaryDataSource(@Qualifier("secondaryDataSourceProperties") DataSourceProperties secondaryDataSourceProperties) {
        return secondaryDataSourceProperties.initializeDataSourceBuilder().type(HikariDataSource.class).build();
    }

    @Bean(name = "secondaryEntityManagerFactory")
    @ConditionalOnProperty(prefix = "trecauth", name = "login", havingValue = "true")
    public LocalContainerEntityManagerFactoryBean secondaryEntityManagerFactory(
            EntityManagerFactoryBuilder secondaryEntityManagerFactoryBuilder, @Qualifier("secondaryDataSource") DataSource secondaryDataSource) {
    	Map<String, String> primaryJpaProperties = new HashMap<>();
        primaryJpaProperties.put("hibernate.dialect", System.getenv("DB_DIALECT"));
        primaryJpaProperties.put("hibernate.hbm2ddl.auto", "update");

        primaryJpaProperties.put("hibernate.enable_lazy_load_no_trans", "true");

        return secondaryEntityManagerFactoryBuilder
                .dataSource(secondaryDataSource)
                .packages("com.trecapps.auth.common.models.secondary")
                .persistenceUnit("secondaryDataSource")
                .properties(primaryJpaProperties)
                .build();
    }

    @Bean(name = "secondaryTransactionManager")
    @ConditionalOnProperty(prefix = "trecauth", name = "login", havingValue = "true")
    public PlatformTransactionManager secondaryTransactionManager(
            @Qualifier("secondaryEntityManagerFactory") EntityManagerFactory secondaryEntityManagerFactory) {

        return new JpaTransactionManager(secondaryEntityManagerFactory);
    }
}
