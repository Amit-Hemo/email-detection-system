function onGmailMessageOpen(e) {
  var header = CardService.newCardHeader().setTitle('Welcome');

  var section = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph().setText(
        'Click the button below to analyze this email for phishing threats.',
      ),
    )
    .addWidget(
      CardService.newTextButton()
        .setText('Scan Email')
        .setOnClickAction(
          CardService.newAction().setFunctionName('handleScanRequest'),
        ),
    );

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(section)
    .build();
}

function handleScanRequest(e) {
  var messageId = e.gmail.messageId;
  var message = GmailApp.getMessageById(messageId);

  var payload = {
    subject: message.getSubject(),
    sender: message.getFrom(),
    body: message.getPlainBody(),
  };

  var options = {
    method: 'post',
    contentType: 'application/json',
    payload: JSON.stringify(payload),
    muteHttpExceptions: true,
  };

  try {
    var apiUrl =
      PropertiesService.getScriptProperties().getProperty('API_URL') ||
      'https://email-detection-system-latest.onrender.com/api/v1/analyze';

    var response = UrlFetchApp.fetch(apiUrl, options);
    var result = JSON.parse(response.getContentText());
    return CardService.newNavigation().pushCard(createResultCard(result));
  } catch (err) {
    Logger.log(err);
    return CardService.newNavigation().pushCard(
      createErrorCard(
        'Oops something wrong happened, please try again later or contact the developer.',
      ),
    );
  }
}

function createResultCard(result) {
  var header = CardService.newCardHeader().setTitle('Scan Result');

  var LABEL = {
    SAFE: 'Safe',
    SUSPICIOUS: 'Suspicious',
    PHISHING: 'Phishing',
  };

  var status = result.classification || 'Unknown';
  var rawScore = result.confidence_score || 0;
  var percentage = rawScore.toFixed(1) + '%';

  var color, description;

  if (status === LABEL.SAFE) {
    color = '#0f9d58'; // Green
    description =
      'Our system analyzed this email and found no significant threats.';
  } else if (status === LABEL.SUSPICIOUS) {
    color = '#f4b400'; // Orange
    description = 'Caution: This email has some red flags. Proceed with care.';
  } else if (status === LABEL.PHISHING) {
    color = '#db4437'; // Red
    description =
      'High Risk: This email strongly matches phishing patterns. Do not interact.';
  } else {
    color = '#757575'; // Gray
    description = 'Unable to determine the threat level. Please try again.';
  }

  var section = CardService.newCardSection()
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Detection Verdict')
        .setText(
          '<b><font color="' +
            color +
            '">' +
            status.toUpperCase() +
            '</font></b>',
        )
        .setWrapText(false),
    )
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('AI Risk Probability')
        .setText('<b>' + percentage + '</b>')
        .setBottomLabel('Likelihood of this email being a phishing attempt')
        .setEndIcon(CardService.newIconImage().setIcon(CardService.Icon.STAR)),
    )
    .addWidget(CardService.newDivider())
    .addWidget(
      CardService.newTextParagraph().setText('<i>' + description + '</i>'),
    );

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(section)
    .build();
}

function createErrorCard(message) {
  var header = CardService.newCardHeader().setTitle('Scan Result');
  var section = CardService.newCardSection().addWidget(
    CardService.newTextParagraph().setText('<b>Error:</b> ' + message),
  );

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(section)
    .build();
}
