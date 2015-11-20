import org.codehaus.groovy.grails.commons.ApplicationAttributes
import org.mindinformatics.grails.domeo.client.profiles.model.DomeoClientProfile
import org.mindinformatics.grails.domeo.client.profiles.model.DomeoClientProfileEntry
import org.mindinformatics.grails.domeo.client.profiles.model.UserAvailableDomeoClientProfile
import org.mindinformatics.grails.domeo.client.profiles.model.UserCurrentDomeoClientProfile
import org.mindinformatics.grails.domeo.dashboard.circles.Circle
import org.mindinformatics.grails.domeo.dashboard.circles.UserCircle
import org.mindinformatics.grails.domeo.dashboard.groups.DefaultGroupPrivacy
import org.mindinformatics.grails.domeo.dashboard.groups.DefaultGroupRoles
import org.mindinformatics.grails.domeo.dashboard.groups.DefaultGroupStatus
import org.mindinformatics.grails.domeo.dashboard.groups.DefaultUserStatusInGroup
import org.mindinformatics.grails.domeo.dashboard.groups.Group
import org.mindinformatics.grails.domeo.dashboard.groups.GroupPrivacy
import org.mindinformatics.grails.domeo.dashboard.groups.GroupRole
import org.mindinformatics.grails.domeo.dashboard.groups.GroupStatus
import org.mindinformatics.grails.domeo.dashboard.groups.UserGroup
import org.mindinformatics.grails.domeo.dashboard.groups.UserStatusInGroup
import org.mindinformatics.grails.domeo.dashboard.security.DefaultRoles
import org.mindinformatics.grails.domeo.dashboard.security.Role
import org.mindinformatics.grails.domeo.dashboard.security.User
import org.mindinformatics.grails.domeo.dashboard.security.UserRole
 
class BootStrap {
	
	def grailsApplication
	def springSecurityService

    def init = { servletContext ->
		
		/*
		String password = 'password'
		
		def roleAdmin = new Role(authority: 'ROLE_ADMIN').save()
		def roleUser = new Role(authority: 'ROLE_USER').save()

		def user = new User(username: 'user',
			password: password, enabled: true).save()
		def admin = new User(username: 'admin',
			password: password, enabled: true).save()

		UserRole.create user, roleUser
		UserRole.create admin, roleUser
		UserRole.create admin, roleAdmin, true
		
		//org.hsqldb.util.DatabaseManager.main()
*/
		log.info  '========================================================================';
		log.info  ' DOMEO ANNOTATION WEB TOOLKIT (v.' +
			grailsApplication.metadata['app.version'] + ", b." +
			grailsApplication.metadata['app.build'] + ")";
			
		separator();
		log.info  ' Designed and developed by Paolo Ciccarese'
		log.info  ' for MIND Informatics Labs directed by Tim Clark'
		log.info  ' A product of Massachusetts General Hospital, Boston, MA, USA (c) 2012'
		
		log.info  '========================================================================';
		log.info  'Bootstrapping....'
				
		separator();
		log.info  '** Configuration externalization: '
		log.info  ' ' +grailsApplication.config.grails.config.locations
		
		separator();
		log.info  '** MongoDB Configuration';
		log.info  ' url        : ' + grailsApplication.config.mongodb.url ;
		log.info  ' database   : ' + grailsApplication.config.mongodb.database ;
		log.info  ' collection : ' + grailsApplication.config.mongodb.collection ;
        
        	separator();
       	        log.info  '** Elastic Search Configuration';
        	log.info  ' ip         : ' + grailsApplication.config.elastico.ip ;
       	        log.info  ' port       : ' + grailsApplication.config.elastico.port ;
                log.info  ' database   : ' + grailsApplication.config.elastico.database ;
                log.info  ' collection : ' + grailsApplication.config.elastico.collection ;
        
		
		// Databse setup
		def ctx=servletContext.getAttribute(ApplicationAttributes.APPLICATION_CONTEXT)
		def dataSource = ctx.dataSource
  
		dataSource.targetDataSource.setMinEvictableIdleTimeMillis((long)1000 * 60 * 60)
		dataSource.targetDataSource.setTimeBetweenEvictionRunsMillis((long)1000 * 60 * 60)
		dataSource.targetDataSource.setNumTestsPerEvictionRun(3)
  
		dataSource.targetDataSource.setTestOnBorrow(true)
		dataSource.targetDataSource.setTestWhileIdle(true)
		dataSource.targetDataSource.setTestOnReturn(true)
		dataSource.targetDataSource.setValidationQuery("SELECT 1")
		
		separator();
		log.info  '** MySQL Configuration';
		log.info  ' url        : ' + dataSource.targetDataSource.url ;
		log.info  ' username   : ' + dataSource.targetDataSource.username ;
		log.info  ' password   : ' + 
			(dataSource.targetDataSource.password!=null?dataSource.targetDataSource.password:"<none>") ;
		
		// Uncomment for full database configuration
		//dataSource.targetDataSource.properties.each { println it }
		
		// PROXY
		separator();
		log.info  '** Proxy Configuration';
		log.info  ' proxy ip   : ' + grailsApplication.config.domeo.proxy.ip ;
		log.info  ' proxy port : ' + grailsApplication.config.domeo.proxy.port ;
				
		// ROLES
		separator();
		log.info  '** System Roles'
		DefaultRoles.values().each {
			if(!Role.findByAuthority(it.value())) { 
				new Role(authority: it.value(), ranking: it.ranking(), label: it.label(), description: it.description()).save(failOnError: true, flush: true)	
				log.info  createdPrefix() + it.value() + ', ' + it.ranking()
			}
		}
		
		// GROUPS
		// ------
		//////////ROLES
		separator();
		log.info  '** Groups Roles'
		DefaultGroupRoles.values().each {
			if(!GroupRole.findByAuthority(it.value())) { 
				new GroupRole(authority: it.value(), ranking: it.ranking(), label: it.label(), description: it.description()).save(failOnError: true)
				log.info  createdPrefix() + it.value() + ', ' + it.ranking()
			}
		}
		//////////STATUS
		separator();
		log.info  '** Groups Status'
		DefaultGroupStatus.values().each {
			if(!GroupStatus.findByValue(it.value())) {
				new GroupStatus(value: it.value(), uuid: it.uuid(), label: it.label(), description: it.description()).save(failOnError: true)
				
			}
		}
		//////////PRIVACY
		separator();
		log.info  '** Groups Privacy'
		DefaultGroupPrivacy.values().each {
			if(!GroupPrivacy.findByValue(it.value())) {
				new GroupPrivacy(value: it.value(), uuid: it.uuid(), label: it.label(), description: it.description()).save(failOnError: true)
				log.info  createdPrefix() + it.value()
			}
		}
		//////////USER STATUS IN GROUP
		separator();
		log.info  "** Users' Status in Group"
		DefaultUserStatusInGroup.values().each {
			if(!UserStatusInGroup.findByValue(it.value())) {
				new UserStatusInGroup(value: it.value(), label: it.label(), description: it.description()).save(failOnError: true)
				log.info  createdPrefix() + it.value()
			}
		}
		
		/*
		// COMMUNITY
		// ---------
		//////////ROLES
		println 'Community roles....'
		DefaultCommunityRoles.values().each {
			CommunityRole.findByAuthority(it.value()) ?:
			new CommunityRole(authority: it.value(), label: it.label(), description: it.description()).save(failOnError: true)
		}
		//////////STATUS
		println 'Community status....'
		DefaultGroupStatus.values().each {
			CommunityStatus.findByValue(it.value()) ?:
			new CommunityStatus(value: it.value(), label: it.label(), description: it.description()).save(failOnError: true)
		}
		//////////PRIVACY
		println 'Community privacy....'
		DefaultCommunityPrivacy.values().each {
			CommunityPrivacy.findByValue(it.value()) ?:
			new CommunityPrivacy(value: it.value(), label: it.label(), description: it.description()).save(failOnError: true)
		}
		//////////USER STATUS IN COMMUNITY
		println 'User status in community....'
		DefaultUserStatusInCommunity.values().each {
			UserStatusInCommunity.findByValue(it.value()) ?:
			new UserStatusInCommunity(value: it.value(), label: it.label(), description: it.description()).save(failOnError: true)
		}
		*/
		
		separator();
		
		def admin = 'admin'
		def adminUser = User.findByUsername(admin) ?: new User(
			firstName: 'Richard',
			lastName: 'Boyce',
			displayName: 'Dr. Boyce',
			affiliation: 'DBMI',
			country: 'USA',
			username: admin,
			password: springSecurityService.encodePassword(admin),
			email: 'admin@commonsemantics.org',
			enabled: true).save(failOnError: true) 
			
			log.info  'admin role 0'
			if (!adminUser.authorities.contains(Role.findByAuthority(DefaultRoles.ADMIN.value()))) {
				log.info  'User role 1'
				UserRole.create(adminUser, Role.findByAuthority(DefaultRoles.ADMIN.value()))
			}
		
			
		def yin2 = 'yin2'
		def accountyin2 = User.findByUsername(yin2) ?: new User(
			firstName: 'Yifan',
			lastName: 'Ning',
			displayName: 'Yifan Ning',
			affiliation: 'DBMI',
			country: 'US',
			username: yin2,
			password: springSecurityService.encodePassword(yin2),

			email: 'pharmgx@gmail.com',
			enabled: true).save(failOnError: true)

			log.info  'yin2 role 0'
			if (!accountyin2.authorities.contains(Role.findByAuthority(DefaultRoles.USER.value()))) {
				log.info  'yin2 role 1'
				UserRole.create(accountyin2, Role.findByAuthority(DefaultRoles.USER.value()))
			}

                

			
	
		log.info   '** Initializing profiles'
		separator();
		
		// -------------------
		//  COMPLETE PROFILES
		// -------------------
		log.info   'Initializing complete biomedical profile'
		
		// Plugins
		def completeProfile = DomeoClientProfile.findByName("Complete Biomedical Profile")?: new DomeoClientProfile(
			name: 'Complete Biomedical Profile',
			description: 'All the tools that Domeo has to offer for biomedicine',
			createdBy: adminUser
		).save(failOnError: true, flash: true)
		
		DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.plugins.annotation.qualifier")?: new DomeoClientProfileEntry(
			profile: completeProfile,
			plugin: "org.mindinformatics.gwt.domeo.plugins.annotation.qualifier",
			status: "enabled"
		).save(failOnError: true, flash: true)
		
		DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.plugins.annotation.nif.antibodies")?: new DomeoClientProfileEntry(
			profile: completeProfile,
			plugin: "org.mindinformatics.gwt.domeo.plugins.annotation.nif.antibodies",
			status: "enabled"
		).save(failOnError: true, flash: true)
		
		DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.plugins.annotation.micropubs")?: new DomeoClientProfileEntry(
			profile: completeProfile,
			plugin: "org.mindinformatics.gwt.domeo.plugins.annotation.micropubs",
			status: "enabled"
		).save(failOnError: true, flash: true)

		DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.plugins.annotation.spls")?: new DomeoClientProfileEntry(
			profile: completeProfile,
			plugin: "org.mindinformatics.gwt.domeo.plugins.annotation.spls",
			status: "enabled"
		).save(failOnError: true, flash: true)

		DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.plugins.annotation.ddi")?: new DomeoClientProfileEntry(
			profile: completeProfile,
			plugin: "org.mindinformatics.gwt.domeo.plugins.annotation.ddi",
			status: "enabled"
		).save(failOnError: true, flash: true)

		
		DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.plugins.resource.pubmed")?: new DomeoClientProfileEntry(
			profile: completeProfile,
			plugin: "org.mindinformatics.gwt.domeo.plugins.resource.pubmed",
			status: "enabled"
		).save(failOnError: true, flash: true)
		
		DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.plugins.resource.pubmedcentral")?: new DomeoClientProfileEntry(
			profile: completeProfile,
			plugin: "org.mindinformatics.gwt.domeo.plugins.resource.pubmedcentral",
			status: "enabled"
		).save(failOnError: true, flash: true)
		
		DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.plugins.resource.omim")?: new DomeoClientProfileEntry(
			profile: completeProfile,
			plugin: "org.mindinformatics.gwt.domeo.plugins.resource.omim",
			status: "enabled"
		).save(failOnError: true, flash: true)
		
		DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.plugins.resource.bioportal")?: new DomeoClientProfileEntry(
			profile: completeProfile,
			plugin: "org.mindinformatics.gwt.domeo.plugins.resource.bioportal",
			status: "enabled"
		).save(failOnError: true, flash: true)
		
		DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.client.component.clipboard")?: new DomeoClientProfileEntry(
			profile: completeProfile,
			plugin: "org.mindinformatics.gwt.domeo.client.component.clipboard",
			status: "enabled"
		).save(failOnError: true, flash: true)
		
		// Features
		DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.feature.branding")?: new DomeoClientProfileEntry(
			profile: completeProfile,
			plugin: "org.mindinformatics.gwt.domeo.feature.branding",
			status: "disabled",
			type: "feature"
		).save(failOnError: true, flash: true)
		
		if(DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.feature.addressbar")) {
			DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.feature.addressbar").status = "enabled"
		} else {
			new DomeoClientProfileEntry(
				profile: completeProfile,
				plugin: "org.mindinformatics.gwt.domeo.feature.addressbar",
				status: "enabled",
				type: "feature"
			).save(failOnError: true, flash: true)
		}
		
		DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.feature.analyze")?: new DomeoClientProfileEntry(
			profile: completeProfile,
			plugin: "org.mindinformatics.gwt.domeo.feature.analyze",
			status: "enabled",
			type: "feature"
		).save(failOnError: true, flash: true)
		
		DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.feature.preferences")?: new DomeoClientProfileEntry(
			profile: completeProfile,
			plugin: "org.mindinformatics.gwt.domeo.feature.preferences",
			status: "enabled",
			type: "feature"
		).save(failOnError: true, flash: true)
		
		if(DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.feature.sharing")) {
			DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.feature.sharing").status = "enabled"
		} else {
			new DomeoClientProfileEntry(
				profile: completeProfile,
				plugin: "org.mindinformatics.gwt.domeo.feature.sharing",
				status: "enabled",
				type: "feature"
			).save(failOnError: true, flash: true)
		}
		
		DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.feature.help")?: new DomeoClientProfileEntry(
			profile: completeProfile,
			plugin: "org.mindinformatics.gwt.domeo.feature.help",
			status: "enabled",
			type: "feature"
		).save(failOnError: true, flash: true)
		
		if(DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.feature.document.general.reference.self")) {
			DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.feature.document.general.reference.self").status = "enabled"
		} else {
			new DomeoClientProfileEntry(
				profile: completeProfile,
				plugin: "org.mindinformatics.gwt.domeo.feature.document.general.reference.self",
				status: "enabled",
				type: "feature"
			).save(failOnError: true, flash: true)
		}
		
		if(DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.feature.document.general.qualifiers.self")) {
			DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.feature.document.general.qualifiers.self").status = "enabled"
		} else {
			new DomeoClientProfileEntry(
				profile: completeProfile,
				plugin: "org.mindinformatics.gwt.domeo.feature.document.general.qualifiers.self",
				status: "enabled",
				type: "feature"
			).save(failOnError: true, flash: true)
		}
		
		if(DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.feature.document.general.bibliography")) {
			DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.feature.document.general.bibliography").status = "enabled"
		} else {
			new DomeoClientProfileEntry(
				profile: completeProfile,
				plugin: "org.mindinformatics.gwt.domeo.feature.document.general.bibliography",
				status: "enabled",
				type: "feature"
			).save(failOnError: true, flash: true)
		}
		
		if(DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.feature.document.general.recommendations")) {
			DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.feature.document.general.recommendations").status = "disabled"
		} else {
			new DomeoClientProfileEntry(
				profile: completeProfile,
				plugin: "org.mindinformatics.gwt.domeo.feature.document.general.recommendations",
				status: "disabled",
				type: "feature"
			).save(failOnError: true, flash: true)
		}
		
		// If not present the text mining summary panel will display
		if(DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.feature.textmining.summary")) {
			DomeoClientProfileEntry.findByProfileAndPlugin(completeProfile, "org.mindinformatics.gwt.domeo.feature.textmining.summary").status = "enabled"
		} else {
			new DomeoClientProfileEntry(
				profile: completeProfile,
				plugin: "org.mindinformatics.gwt.domeo.feature.textmining.summary",
				status: "enabled",
				type: "feature"
			).save(failOnError: true, flash: true)
		}
		
		// ----------------
		//  DDI PROFILES
		// ----------------
		separator();
		log.info   'Initializing DDI profiles'
		def DDIProfile = DomeoClientProfile.findByName("DDI profile")?: new DomeoClientProfile(
			name: 'DDI profile',
			description: 'DDI profile: notes and commenting',
			createdBy: adminUser
		).save(failOnError: true, flash: true)


                DomeoClientProfileEntry.findByProfileAndPlugin(DDIProfile, "org.mindinformatics.gwt.domeo.plugins.annotation.ddi")?: new DomeoClientProfileEntry(
			profile: DDIProfile,
			plugin: "org.mindinformatics.gwt.domeo.plugins.annotation.ddi",
			status: "enabled"
		).save(failOnError: true, flash: true)
		


                // ----------------
		//  SPLs PROFILES
		// ----------------
		separator();
		log.info   'Initializing SPL profiles'
		def SPLProfile = DomeoClientProfile.findByName("SPL profile")?: new DomeoClientProfile(
			name: 'SPL profile',
			description: 'SPL profile: notes and commenting',
			createdBy: adminUser
		).save(failOnError: true, flash: true)


		DomeoClientProfileEntry.findByProfileAndPlugin(SPLProfile, "org.mindinformatics.gwt.domeo.plugins.annotation.spls")?: new DomeoClientProfileEntry(
			profile: SPLProfile,
			plugin: "org.mindinformatics.gwt.domeo.plugins.annotation.spls",
			status: "enabled"
		).save(failOnError: true, flash: true)


		separator();


		// Initialize available profiles (the ones defined above)
		log.info   'Initializing available profiles'

		log.info   'Administrator profiles'
		UserAvailableDomeoClientProfile.findByUserAndProfile(adminUser, completeProfile)?: new UserAvailableDomeoClientProfile(
			user: adminUser,
			profile: completeProfile
		).save(failOnError: true, flash: true)

		UserAvailableDomeoClientProfile.findByUserAndProfile(adminUser, SPLProfile)?: new UserAvailableDomeoClientProfile(
			user: adminUser,
			profile: SPLProfile
		).save(failOnError: true, flash: true)


                UserAvailableDomeoClientProfile.findByUserAndProfile(adminUser, DDIProfile)?: new UserAvailableDomeoClientProfile(
			user: adminUser,
			profile: DDIProfile
		).save(failOnError: true, flash: true)

		
		// ningyifan profile
		log.info   'yin2 profiles'
		UserAvailableDomeoClientProfile.findByUserAndProfile(accountyin2, DDIProfile)?: new UserAvailableDomeoClientProfile(
			user: accountyin2,
			profile: DDIProfile
		).save(failOnError: true, flash: true)
		
                UserAvailableDomeoClientProfile.findByUserAndProfile(accountyin2, SPLProfile)?: new UserAvailableDomeoClientProfile(
			user: accountyin2,
			profile: SPLProfile
		).save(failOnError: true, flash: true)

                UserAvailableDomeoClientProfile.findByUserAndProfile(accountyin2, completeProfile)?: new UserAvailableDomeoClientProfile(
			user: accountyin2,
			profile: completeProfile
		).save(failOnError: true, flash: true)

		// katrina profile
                def accountkatrina = User.findByUsername('katrina')
                if (accountkatrina) {
                log.info   'katrina profiles'
                UserAvailableDomeoClientProfile.findByUserAndProfile(accountkatrina, SPLProfile)?: new UserAvailableDomeoClientProfile(
			user: accountkatrina,
			profile: SPLProfile
		).save(failOnError: true, flash: true) 

		UserAvailableDomeoClientProfile.findByUserAndProfile(accountkatrina, DDIProfile)?: new UserAvailableDomeoClientProfile(
			user: accountkatrina,
			profile: DDIProfile
		).save(failOnError: true, flash: true)
		}

		// amy profile
                def accountamygrizzle = User.findByUsername('amygrizzle')
                if (accountamygrizzle) {
		
                log.info   'amygrizzle profiles'
                // UserAvailableDomeoClientProfile.findByUserAndProfile(accountamygrizzle, SPLProfile)?: new UserAvailableDomeoClientProfile(
		// 	user: accountamygrizzle,
		// 	profile: SPLProfile
		// ).save(failOnError: true, flash: true) 

		UserAvailableDomeoClientProfile.findByUserAndProfile(accountamygrizzle, DDIProfile)?: new UserAvailableDomeoClientProfile(
			user: accountamygrizzle,
			profile: DDIProfile
		).save(failOnError: true, flash: true)
		}
                
		// pgxconsensus profile
                def accountpgxconsensus = User.findByUsername('pgxconsensus')
                if (accountpgxconsensus) {
		
                log.info   'pgxconsensus profiles'
                UserAvailableDomeoClientProfile.findByUserAndProfile(accountpgxconsensus, SPLProfile)?: new UserAvailableDomeoClientProfile(
			user: accountpgxconsensus,
			profile: SPLProfile
		).save(failOnError: true, flash: true) }



                def accountphilp = User.findByUsername('philempey')
                if (accountphilp) {
                log.info   'philp profiles'
                UserAvailableDomeoClientProfile.findByUserAndProfile(accountphilp, SPLProfile)?: new UserAvailableDomeoClientProfile(
			user: accountphilp,
			profile: SPLProfile
		).save(failOnError: true, flash: true)
                }

                def accountharry = User.findByUsername('harry')
                if (accountharry) {
                log.info   'harry profiles'
                UserAvailableDomeoClientProfile.findByUserAndProfile(accountharry, SPLProfile)?: new UserAvailableDomeoClientProfile(
			user: accountharry,
			profile: SPLProfile
		).save(failOnError: true, flash: true)
                }

                def accountsolo = User.findByUsername('sadams')
                if (accountsolo) {
                    log.info   'solomon profiles'
                    UserAvailableDomeoClientProfile.findByUserAndProfile(accountsolo, SPLProfile)?: new UserAvailableDomeoClientProfile(
			user: accountsolo,
			profile: SPLProfile
		    ).save(failOnError: true, flash: true)
                }

                def accountallison = User.findByUsername('dohertyallison')
                if (accountallison) {
                log.info   'allison profiles'
                UserAvailableDomeoClientProfile.findByUserAndProfile(accountallison, SPLProfile)?: new UserAvailableDomeoClientProfile(
			user: accountallison,
			profile: SPLProfile
		).save(failOnError: true, flash: true) }

                def accountJocelyn = User.findByUsername('JHatfield')
                if(accountJocelyn) {
                log.info   'Jocelyn profiles'
                UserAvailableDomeoClientProfile.findByUserAndProfile(accountJocelyn, SPLProfile)?: new UserAvailableDomeoClientProfile(
			user: accountJocelyn,
			profile: SPLProfile
		).save(failOnError: true, flash: true) }

                def accountwwilson624 = User.findByUsername('wwilson624')
                if (accountwwilson624) {
                log.info   'William profiles'
                    UserAvailableDomeoClientProfile.findByUserAndProfile(accountwwilson624, SPLProfile)?: new UserAvailableDomeoClientProfile(
			    user: accountwwilson624,
			    profile: SPLProfile
		    ).save(failOnError: true, flash: true)
                }

                def accountAcockerham = User.findByUsername('Acockerham')
                if (accountAcockerham) {
                log.info   'Alex profiles'
                    UserAvailableDomeoClientProfile.findByUserAndProfile(accountAcockerham, SPLProfile)?: new UserAvailableDomeoClientProfile(
			    user: accountAcockerham,
			    profile: SPLProfile
		    ).save(failOnError: true, flash: true)
                }

                def accountmdiduch23 = User.findByUsername('mdiduch23')
                if (accountmdiduch23) {
                log.info   'Michael profiles'
                    UserAvailableDomeoClientProfile.findByUserAndProfile(accountmdiduch23, SPLProfile)?: new UserAvailableDomeoClientProfile(
			    user: accountmdiduch23,
			    profile: SPLProfile
		    ).save(failOnError: true, flash: true)
                }

                def accountfwz1 = User.findByUsername('fwz1')
                if (accountfwz1) {
                log.info   'feng yee'
                    UserAvailableDomeoClientProfile.findByUserAndProfile(accountfwz1, SPLProfile)?: new UserAvailableDomeoClientProfile(
			    user: accountfwz1,
			    profile: SPLProfile
		    ).save(failOnError: true, flash: true)
                }
                
                def accountllh39 = User.findByUsername('llh39')
                if (accountllh39) {
                log.info   'linda huang'
                    UserAvailableDomeoClientProfile.findByUserAndProfile(accountllh39, SPLProfile)?: new UserAvailableDomeoClientProfile(
			    user: accountllh39,
			    profile: SPLProfile
		    ).save(failOnError: true, flash: true)
                }


                def accountexpert1 = User.findByUsername('expert1')
                if(accountexpert1) {
                log.info   'expert1 profiles'
                UserAvailableDomeoClientProfile.findByUserAndProfile(accountexpert1, DDIProfile)?: new UserAvailableDomeoClientProfile(
			user: accountexpert1,
			profile: DDIProfile
		).save(failOnError: true, flash: true) }

                def accountexpert2 = User.findByUsername('expert2')
                if (accountexpert2) {
                log.info   'expert2 profiles'
                UserAvailableDomeoClientProfile.findByUserAndProfile(accountexpert2, DDIProfile)?: new UserAvailableDomeoClientProfile(
			user: accountexpert2,
			profile: DDIProfile
		).save(failOnError: true, flash: true) }

                
                def accountnonexpert1 = User.findByUsername('nonexpert1')
                if (accountnonexpert1) {
                log.info   'nonexpert1 profiles'
                UserAvailableDomeoClientProfile.findByUserAndProfile(accountnonexpert1, DDIProfile)?: new UserAvailableDomeoClientProfile(
			user: accountnonexpert1,
			profile: DDIProfile
		).save(failOnError: true, flash: true) }

                
                def accountnonexpert2 = User.findByUsername('nonexpert2')
                if (accountnonexpert2) {
                log.info   'nonexpert2 profiles'
                UserAvailableDomeoClientProfile.findByUserAndProfile(accountnonexpert2, DDIProfile)?: new UserAvailableDomeoClientProfile(
			user: accountnonexpert2,
			profile: DDIProfile
		).save(failOnError: true, flash: true) }

                def accountnonexpert3 = User.findByUsername('nonexpert3')
                if (accountnonexpert3) {
                log.info   'nonexpert3 profiles'
                UserAvailableDomeoClientProfile.findByUserAndProfile(accountnonexpert3, DDIProfile)?: new UserAvailableDomeoClientProfile(
			user: accountnonexpert3,
			profile: DDIProfile
		).save(failOnError: true, flash: true) }

                def accounttestDDI1 = User.findByUsername('testDDI1')
                if (accounttestDDI1) {
                log.info   'testDDI1 profiles'
                UserAvailableDomeoClientProfile.findByUserAndProfile(accounttestDDI1, DDIProfile)?: new UserAvailableDomeoClientProfile(
			user: accounttestDDI1,
			profile: DDIProfile
		).save(failOnError: true, flash: true) }

                def accounttestDDI2 = User.findByUsername('testDDI2')
                if (accounttestDDI2) {
                log.info   'testDDI2 profiles'
                UserAvailableDomeoClientProfile.findByUserAndProfile(accounttestDDI2, DDIProfile)?: new UserAvailableDomeoClientProfile(
			user: accounttestDDI2,
			profile: DDIProfile
		).save(failOnError: true, flash: true) }

                separator();


		log.info   '** Initializing current profiles'

		log.info   'Administrator current profile'
		UserCurrentDomeoClientProfile.findByUser(adminUser)?: new UserCurrentDomeoClientProfile(
			user: adminUser,
			currentProfile: completeProfile
		).save(failOnError: true, flash: true)
		
		log.info   'yin2 current profile'
		UserCurrentDomeoClientProfile.findByUser(accountyin2)?: new UserCurrentDomeoClientProfile(
			user: accountyin2,
			currentProfile: DDIProfile
		).save(failOnError: true, flash: true)
    
                if (accountkatrina) {
                log.info   'katrina current profile'
		UserCurrentDomeoClientProfile.findByUser(accountkatrina)?: new UserCurrentDomeoClientProfile(
			user: accountkatrina,
			currentProfile: SPLProfile
		).save(failOnError: true, flash: true) }
              
                if (accountphilp) {
                log.info   'philp current profile'
		UserCurrentDomeoClientProfile.findByUser(accountphilp)?: new UserCurrentDomeoClientProfile(
			user: accountphilp,
			currentProfile: SPLProfile
		).save(failOnError: true, flash: true) }

                if (accountpgxconsensus) {
                log.info   'pgxconsensus current profile'
		UserCurrentDomeoClientProfile.findByUser(accountpgxconsensus)?: new UserCurrentDomeoClientProfile(
			user: accountpgxconsensus,
			currentProfile: SPLProfile
		).save(failOnError: true, flash: true) }

                if (accountharry) {
                log.info   'harry current profile'
		UserCurrentDomeoClientProfile.findByUser(accountharry)?: new UserCurrentDomeoClientProfile(
			user: accountharry,
			currentProfile: SPLProfile
		).save(failOnError: true, flash: true) }
		
                if (accountsolo) {
                log.info   'solomon current profile'
		UserCurrentDomeoClientProfile.findByUser(accountsolo)?: new UserCurrentDomeoClientProfile(
			user: accountsolo,
			currentProfile: SPLProfile
		).save(failOnError: true, flash: true) }

                if (accountallison) {
                log.info   'allison current profile'
		UserCurrentDomeoClientProfile.findByUser(accountallison)?: new UserCurrentDomeoClientProfile(
			user: accountallison,
			currentProfile: SPLProfile
		).save(failOnError: true, flash: true) }

                if(accountJocelyn) {
                log.info   'Jocelyn current profile'
		UserCurrentDomeoClientProfile.findByUser(accountJocelyn)?: new UserCurrentDomeoClientProfile(
			user: accountJocelyn,
			currentProfile: SPLProfile
		).save(failOnError: true, flash: true) }

                if (accountwwilson624){
                    log.info   'William current profile'
		    UserCurrentDomeoClientProfile.findByUser(accountwwilson624)?: new UserCurrentDomeoClientProfile(
			user: accountwwilson624,
			currentProfile: SPLProfile
		    ).save(failOnError: true, flash: true)
                }

                if (accountAcockerham){
                    log.info   'Alex current profile'
		    UserCurrentDomeoClientProfile.findByUser(accountAcockerham)?: new UserCurrentDomeoClientProfile(
			user: accountAcockerham,
			currentProfile: SPLProfile
		    ).save(failOnError: true, flash: true)
                }

                if (accountmdiduch23){
                    log.info   'Michael current profile'
		    UserCurrentDomeoClientProfile.findByUser(accountmdiduch23)?: new UserCurrentDomeoClientProfile(
			user: accountmdiduch23,
			currentProfile: SPLProfile
		    ).save(failOnError: true, flash: true)
                }


                if (accountexpert1) {
                log.info   'expert1 current profile'
		UserCurrentDomeoClientProfile.findByUser(accountexpert1)?: new UserCurrentDomeoClientProfile(
			user: accountexpert1,
			currentProfile: DDIProfile
		).save(failOnError: true, flash: true) }

                if (accountexpert2) { 
                log.info   'expert2 current profile'
		UserCurrentDomeoClientProfile.findByUser(accountexpert2)?: new UserCurrentDomeoClientProfile(
			user: accountexpert2,
			currentProfile: DDIProfile
		).save(failOnError: true, flash: true) }

                if (accountnonexpert1) {
                log.info   'nonexpert1 current profile'
		UserCurrentDomeoClientProfile.findByUser(accountnonexpert1)?: new UserCurrentDomeoClientProfile(
			user: accountnonexpert1,
			currentProfile: DDIProfile
		).save(failOnError: true, flash: true) }

                if (accountnonexpert2) {
                log.info   'nonexpert2 current profile'
		UserCurrentDomeoClientProfile.findByUser(accountnonexpert2)?: new UserCurrentDomeoClientProfile(
			user: accountnonexpert2,
			currentProfile: DDIProfile
		).save(failOnError: true, flash: true) }

                if (accountnonexpert3) {
                log.info   'nonexpert3 current profile'
		UserCurrentDomeoClientProfile.findByUser(accountnonexpert3)?: new UserCurrentDomeoClientProfile(
			user: accountnonexpert3,
			currentProfile: DDIProfile
		).save(failOnError: true, flash: true) }

                if (accounttestDDI1) {
                log.info   'testDDI1 current profile'
		UserCurrentDomeoClientProfile.findByUser(accounttestDDI1)?: new UserCurrentDomeoClientProfile(
			user: accounttestDDI1,
			currentProfile: DDIProfile
		).save(failOnError: true, flash: true) }

                if (accounttestDDI2) {
                log.info   'testDDI2 current profile'
		UserCurrentDomeoClientProfile.findByUser(accounttestDDI2)?: new UserCurrentDomeoClientProfile(
			user: accounttestDDI2,
			currentProfile: DDIProfile
		).save(failOnError: true, flash: true) }

		separator();

		log.info  'Bootstrapping complete!'
		log.info  '========================================================================';
    }
	def separator = {
		log.info  '------------------------------------------------------------------------';
	}
	def createdPrefix = {
		return ' created    : ';
	}
    def destroy = {
    }
}
