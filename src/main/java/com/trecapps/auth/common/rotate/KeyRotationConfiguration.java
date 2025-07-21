package com.trecapps.auth.common.rotate;

import org.quartz.*;

import static org.quartz.SimpleScheduleBuilder.simpleSchedule;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.quartz.SchedulerFactoryBean;

import java.util.*;
import java.util.Calendar;

@Configuration
public class KeyRotationConfiguration {

    @Autowired
    private ApplicationContext applicationContext;

    int safeParse(String value, int defaultValue, int max) {
        try {
            int ret = Integer.parseInt(value);
            if(ret > max)
                throw new IllegalArgumentException(String.format("Provided Value %d is greater than the maximum allowed: %d", ret, max));
            return ret;
        } catch(NumberFormatException ignore){
            return defaultValue;
        }
    }

    SimpleScheduleBuilder setInterval(SimpleScheduleBuilder builder, String interval) {
        char end = interval.charAt(interval.toUpperCase(Locale.ROOT).length() - 1);
        int count = 0;
        if(List.of('W', 'D', 'H', 'M', 'S').contains(end))
            count = Integer.parseInt(interval.substring(0, interval.length() - 1));
        else count = Integer.parseInt(interval);

        int multiplier = 1;

        switch(end) {
            case 'W':
                multiplier *= 7;
            case 'D':
                multiplier *= 24;
            case 'H':
            {
                return builder.withIntervalInHours(count * multiplier);
            }
            case 'M':
            {
                return builder.withIntervalInMinutes(count);
            }
            case 'S': {
                return builder.withIntervalInSeconds(count);
            }
            default:
            {
                return builder.withIntervalInHours(count * multiplier);
            }
        }
    }

    Calendar getCalendarStart(String calendar) {
        Calendar now = Calendar.getInstance();
        if(calendar.startsWith("ofweek-")){
            calendar = calendar.substring(7);
            // there can only be 1 digit, so read first char
            int day = Integer.parseInt(calendar.substring(0, 1));
            if(day < 1 || day > 7)
                throw new IllegalArgumentException("When specifying a start point for scheduling with 'ofweek-', you need a value between 1-7 inclusive!");
            calendar = calendar.substring(1).trim();
            String[] values = (String[]) Arrays.stream(calendar.split(":")).map(String::trim).toArray();

            int[] time = {0,0,0,0};
            int[] maxTime = {23,59,59,999};
            int index = 0;
            for(String v : values){
                if(index < time.length)
                    time[index] = safeParse(v, 0, maxTime[index++]);
            }
            Calendar target = new Calendar.Builder()
                    .set(Calendar.YEAR, now.get(Calendar.YEAR))
                    .set(Calendar.DAY_OF_WEEK, day)
                    .set(Calendar.HOUR, time[0])
                    .set(Calendar.MINUTE, time[1])
                    .set(Calendar.SECOND, time[2])
                    .set(Calendar.MILLISECOND, time[3])
                    .set(Calendar.WEEK_OF_YEAR, now.get(Calendar.WEEK_OF_YEAR))
                    .build();

            if(now.after(target))
                target.set(Calendar.WEEK_OF_YEAR, target.get(Calendar.WEEK_OF_YEAR) + 1);
            return target;
        } else {
            // To-Do: Implement alternative format


            // End To-Do

            return null;
        }
    }

    @Bean(name="rotateJobDetail")
    @ConditionalOnProperty(prefix = "trecauth.rotate", name = "do-rotate", havingValue = "true")
    public JobDetail rotateJobDetail() {
        return JobBuilder.newJob().ofType(KeyRotationUpdater.class)
                .storeDurably()
                .withIdentity("Qrtz_Rotate_Detail")
                .withDescription("Allows app to retrieve a new Key from the source (assuming one has been set)")
                .build();
    }

    @Bean(name="rotateJobTrigger")
    @ConditionalOnBean(value = JobDetail.class, name = "rotateJobDetail")
    public Trigger rotateTrigger(
            @Qualifier("rotateJobDetail") JobDetail job,
            @Value("${trecauth.rotate.rotate-interval:7D}")String interval,
            @Value("${trecauth.rotate.rotate-start:ofweek-1 12:00:00") String start,
            @Value("${trecauth.rotate.rotate-cron-schedule:#{NULL}}")String cron
            ) {

        if(cron != null){
            CronScheduleBuilder scheduleBuilder = CronScheduleBuilder.cronSchedule(cron);

            return TriggerBuilder.newTrigger()
                    .forJob(job)
                    .withSchedule(scheduleBuilder)
                    .build();
        }

        SimpleScheduleBuilder scheduleBuilder = setInterval(simpleSchedule(), interval);

        return TriggerBuilder.newTrigger()
                .forJob(job)
                .withSchedule(scheduleBuilder)
                .startAt(getCalendarStart(start).getTime())
                .build();
    }

    @Bean(name="updateJobDetail")
    @ConditionalOnProperty(prefix = "trecauth.rotate", name = "do-update", havingValue = "true")
    public JobDetail updateJobDetail() {
        return JobBuilder.newJob().ofType(KeyRotationPublisher.class)
                .storeDurably()
                .withIdentity("Qrtz_Update_Detail")
                .withDescription("Allows an app to publish a new version of the Key Pair to facilitate JWT key rotation")
                .build();
    }

    @Bean(name="updateJobTrigger")
    @ConditionalOnProperty(prefix = "trecauth.rotate", name = "update-cron-schedule", matchIfMissing = true)
    @ConditionalOnBean(value=JobDetail.class, name="updateJobDetail")
    public Trigger updateTrigger(
            @Qualifier("updateJobDetail") JobDetail job,
            @Value("${trecauth.rotate.update-interval:7D}")String interval,
            @Value("${trecauth.rotate.update-start:ofweek-1 0:00:00") String start,
            @Value("${trecauth.rotate.update-cron-schedule:#{NULL}}")String cron

    ) {

        if(cron != null){
            CronScheduleBuilder scheduleBuilder = CronScheduleBuilder.cronSchedule(cron);

            return TriggerBuilder.newTrigger()
                    .forJob(job)
                    .withSchedule(scheduleBuilder)
                    .build();
        }
        SimpleScheduleBuilder scheduleBuilder = setInterval(simpleSchedule(), interval);

        return TriggerBuilder.newTrigger()
                .forJob(job)
                .withSchedule(scheduleBuilder)
                .startAt(getCalendarStart(start).getTime())
                .build();
    }


    @Bean
    @ConditionalOnBean(Trigger.class)
    public SchedulerFactoryBean quartzScheduler(
            @Autowired(required = false)
            @Qualifier("rotateJobTrigger") Trigger rotateTrigger,
            @Autowired(required = false)
            @Qualifier("updateJobTrigger") Trigger updateTrigger,
            @Autowired(required = false)
            @Qualifier("rotateJobDetail") JobDetail rotateJobDetail,
            @Autowired(required = false)
            @Qualifier("updateJobDetail") JobDetail updateJobDetail
    ) {
        List<Trigger> triggerList = new ArrayList<>(2);
        if(rotateTrigger != null)
            triggerList.add(rotateTrigger);
        if(updateTrigger != null)
            triggerList.add(updateTrigger);


        List<JobDetail> detailList = new ArrayList<>(2);
        if(rotateJobDetail != null)
            detailList.add(rotateJobDetail);
        if(updateJobDetail != null)
            detailList.add(updateJobDetail);

        SchedulerFactoryBean quartzScheduler = new SchedulerFactoryBean();


        AutowiringSpringBeanJobFactory jobFactory = new AutowiringSpringBeanJobFactory();
        jobFactory.setApplicationContext(applicationContext);
        quartzScheduler.setJobFactory(jobFactory);

        quartzScheduler.setTriggers(triggerList.toArray(new Trigger[0]));
        quartzScheduler.setJobDetails(detailList.toArray(new JobDetail[0]));

        return quartzScheduler;
    }

}
