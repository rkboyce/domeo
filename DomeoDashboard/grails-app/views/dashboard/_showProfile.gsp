<%-- by Paolo Ciccarese --%>
<%-- 
Parameters list
 1) user | instance of GroupCreateCommand
Stylesheet
 1) fieldError | background and font color in erroneous text fields
--%>
<div class="sectioncontainer">
<g:if test="${params.msgSuccess!=null}">
	<div class="successMessage">
	${params.msgSuccess}
	</div>
</g:if>
<div class="dialog" style="width: 330px">
    <fieldset>
		<table style="width: 460px">
			<tbody>
				<%-- 
				<tr class="sprop">
					<td valign="top" colspan="2"  align="center">
						<img src="${resource(dir:'images/dashboard',file:'no_image.gif',plugin:'users-module')}" width="200px" />
					</td>
				</tr>
				--%>
				<tr class="sprop">
					<td valign="top" width="120px"  align="left">
						<label for="firstName">First name</label>
					</td>
					<td valign="top" width="265px" align="left">
						${user?.firstName}
					</td>
				</tr>
				<tr class="sprop">
					<td valign="top"  align="left">
						<label for="lastName">Last name</label>
					</td>
					<td valign="top" align="left">
						${user?.lastName}
					</td>
				</tr>
				<tr class="sprop">
					<td valign="top"  align="left">
						<label for="displayName">Display name</label>
					</td>
					<td valign="top" align="left">
						${user?.displayName}
					</td>
				</tr>
				<tr class="sprop">
					<td valign="top"  align="left">
						<label for="displayName">Username</label>
					</td>
					<td valign="top" align="left">
						${user?.username}
					</td>
				</tr>
				<tr class="sprop">
					<td valign="top"  align="left">
						<label for="displayName">Email</label>
					</td>
					<td valign="top" align="left">
						${user?.email}
					</td>
				</tr>
				<tr class="sprop">
					<td valign="top"  align="left">
						<label for="displayName">Affiliation</label>
					</td>
					<td valign="top" align="left">
						${user?.affiliation}
					</td>
				</tr>
				<tr class="sprop">
					<td valign="top"  align="left">
						<label for="displayName">Country</label>
					</td>
					<td valign="top" align="left">
						${user?.country}
					</td>
				</tr>
				<tr class="sprop">
					<td valign="top" width="140px" align="left">
						<label for="userRole">Role</label>
					</td>
					<td valign="top" colspan="2" align="left">
						<div>
							<g:each in="${userRoles}">
								${it.label}
							</g:each>
						</div>
					</td>
				</tr>
				<tr class="sprop">
					<td valign="top" width="140px" align="left">
						<label for="userRole">Account Status</label>
					</td>
					<td valign="top" colspan="2" align="left">
						<div>
							${user?.status}
						</div>
					</td>
				</tr>
				<tr class="sprop">
					<td colspan="2">
						<div class="buttons">
							<g:form>
								<g:hiddenField name="id" value="${loggedUser?.id}" /> 
								<g:hiddenField name="user" value="${loggedUser?.id}" /> 
								<g:hiddenField name="redirect" value="showProfile" />
								<span class="button">
									<g:if test="${user?.id==loggedUser?.id}">
										<g:actionSubmit class="edit" action="editProfile" value="${message(code: 'default.button.edit.account.label', default: 'Edit profile')}" />
									</g:if>
									<g:else>
										<g:actionSubmit class="edit" action="editProfile" value="${message(code: 'default.button.edit.account.label', default: 'Edit user profile')}" />
									</g:else>
									<g:if test="${fieldValue(bean: user, field: 'accountLocked') == 'true'}">
										<span class="button">
											<g:actionSubmit class="unlock" action="unlockUser" value="${message(code: 'default.button.unlock.account.label', default: 'Unlock')}" />
										</span>
									</g:if>
									<g:elseif test="${fieldValue(bean: user, field: 'accountLocked') == 'false'}">
										<span class="button">
											<g:actionSubmit class="lock" action="lockUser" value="${message(code: 'default.button.lock.account.label', default: 'Lock')}"
											onclick="return confirm('${message(code: 'default.button.lock.account.confirm.message', default: 'Are you sure you want to lock this account?')}');" />
										</span>
									</g:elseif>
									<g:if test="${fieldValue(bean: user, field: 'enabled') == 'true'}">
										<span class="button">
											<g:actionSubmit class="disable" action="disableUser" value="${message(code: 'default.button.disable.account.label', default: 'Disable')}" 
											onclick="return confirm('${message(code: 'default.button.disable.account.confirm.message', default: 'Are you sure you want to disable this account?')}');"/>
										</span>
									</g:if>
									<g:elseif test="${fieldValue(bean: user, field: 'enabled') == 'false'}">
										<span class="button">
											<g:actionSubmit class="enable" action="enableUser" value="${message(code: 'default.button.enable.account.label', default: 'Enable')}" />
										</span>
									</g:elseif>
									<span class="button">
										<g:actionSubmit class="password" action="resetUserPassword" value="${message(code: 'default.button.resetpwd.label', default: 'Reset password')}" 
										onclick="return confirm('${message(code: 'default.button.resetpwd.account.confirm.message', default: 'Are you sure you want to reset the password?')}');"/>
									</span>
								</span>
							</g:form>
						</div>
					</td>
				</tr>
			</tbody>
		</table>
</fieldset>
<br/>
</div>
</div>
