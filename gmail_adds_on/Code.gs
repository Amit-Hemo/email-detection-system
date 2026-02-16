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
    var response = UrlFetchApp.fetch(
      'https://email-detection-system-latest.onrender.com/api/v1/analyze',
      options,
    );
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
  var color, description;

  if (status === LABEL.SAFE) {
    color = '#0f9d58'; // Green
    description = 'Our heuristics suggest this email is safe to interact with.';
  } else if (status === LABEL.SUSPICIOUS) {
    color = '#f4b400'; // Orange/Yellow
    description =
      'Caution: This email contains unusual patterns. Do not click links.';
  } else if (status === LABEL.PHISHING) {
    color = '#db4437'; // Red
    description = 'High Risk: This email matches known phishing signatures!';
  } else {
    color = '#000000'; //Black
    description = 'Unknown Label,';
  }

  var section = CardService.newCardSection()
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Result')
        .setText(
          '<b><font color="' +
          color +
          '">' +
          result.classification.toUpperCase() +
          '</font></b>',
        )
        .setWrapText(false),
    )
    .addWidget(CardService.newTextParagraph().setText(description));

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
